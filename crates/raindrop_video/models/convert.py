#!/usr/bin/env python3
"""Rebuilds `selfie_segmenter_v1.onnx` from Google's published TensorFlow Lite
model, and checks the result against it.

The committed ONNX file came out of exactly this script. It is here rather than
described in prose because two of the four steps are not obvious, and a reader
who has to rediscover them will not know whether what they end up with is the
same model.

Run it from this folder, in a virtualenv built as `README.md` says:

    python3 -m venv venv
    ./venv/bin/pip install 'tensorflow==2.17.1' 'tf2onnx==1.16.1' onnx \\
        'tf-keras==2.17.0' onnxruntime 'protobuf==4.25.5' pillow
    ./venv/bin/python convert.py

It writes `selfie_segmenter_v1.onnx` next to itself and prints the SHA-256 of
both files, which belong in the table in `README.md`.
"""

import hashlib
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

import numpy as np
import onnx
from onnx import numpy_helper

HERE = Path(__file__).parent
TFLITE = HERE / "selfie_segmenter.tflite"
RAW_ONNX = HERE / "selfie_segmenter_raw.onnx"
ONNX = HERE / "selfie_segmenter_v1.onnx"

SOURCE_URL = (
    "https://storage.googleapis.com/mediapipe-models/image_segmenter/"
    "selfie_segmenter/float16/latest/selfie_segmenter.tflite"
)

# MediaPipe's own test pictures, used only to check the conversion. Nothing is
# committed: they are fetched when this runs and thrown away.
TEST_IMAGES = ["portrait.jpg", "segmentation_input_rotation0.jpg"]
TEST_IMAGE_URL = "https://storage.googleapis.com/mediapipe-assets/{}"

# What `segmentation::onnx` pins with `with_input_fact`. Asserted here so a
# model that disagrees is caught during conversion rather than at load.
SHAPE_IN = (1, 256, 256, 3)
SHAPE_OUT = (1, 256, 256, 1)


def fetch(url: str, into: Path) -> Path:
    if not into.exists():
        print(f"fetching {into.name}")
        urllib.request.urlretrieve(url, into)
    return into


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def convert() -> None:
    """Step one: tf2onnx, at **opset 17**.

    The opset matters. At 13 the conversion also fails on eleven `HardSwish`
    nodes, because ONNX only gained that operator at opset 14; the result loads
    and then cannot run. 17 leaves exactly one unconvertible node, which the
    next step deals with.
    """
    print("converting with tf2onnx")
    subprocess.run(
        [
            sys.executable, "-m", "tf2onnx.convert",
            "--opset", "17",
            "--tflite", str(TFLITE),
            "--output", str(RAW_ONNX),
        ],
        check=True,
        # tf2onnx imports TensorFlow, which with TensorFlow 2.16 and later
        # means Keras 3 unless it is told otherwise; TF_USE_LEGACY_KERAS is
        # what keeps `import tf2onnx` from failing on it.
        env={**os.environ, "TF_USE_LEGACY_KERAS": "1", "TF_CPP_MIN_LOG_LEVEL": "2"},
    )


def replace_the_custom_op() -> None:
    """Step two: rewrite MediaPipe's one custom operator as the standard ONNX
    operators it is.

    `TFL_Convolution2DTransposeBias` is a TFLite *custom* op — a fused
    transpose convolution and bias add — and tf2onnx has no conversion for it,
    so it leaves the node in place with its TFLite name. Nothing can execute
    that: tract refuses the model and so does onnxruntime.

    It is the model's final upsample, 128x128x16 to 256x256x1. Its weights are
    TFLite transpose-conv layout `[out, kH, kW, in]` = `[1, 2, 2, 16]` and its
    bias is `[1]`, so with a 2x2 kernel doubling the resolution the stride is 2
    and there is no padding — the shapes leave no other possibility. ONNX
    `ConvTranspose` wants NCHW and weights as `[in, out, kH, kW]`, hence the
    transposes around it and the permuted weights.
    """
    model = onnx.load(RAW_ONNX)
    graph = model.graph
    initialisers = {i.name: i for i in graph.initializer}

    victims = [n for n in graph.node if n.op_type == "TFL_Convolution2DTransposeBias"]
    if not victims:
        raise SystemExit(
            "no TFL_Convolution2DTransposeBias node: tf2onnx may have learned to "
            "convert it, in which case delete this step after checking the output"
        )
    if len(victims) > 1:
        raise SystemExit(f"expected one custom node, found {len(victims)}")

    node = victims[0]
    source, weights_name, bias_name = node.input
    (output,) = node.output

    weights = numpy_helper.to_array(initialisers[weights_name])
    if weights.shape != (1, 2, 2, 16):
        raise SystemExit(f"unexpected transpose-conv weights {weights.shape}")

    permuted = np.ascontiguousarray(weights.transpose(3, 0, 1, 2))
    graph.initializer.append(numpy_helper.from_array(permuted, "segment_convtranspose_w"))

    index = list(graph.node).index(node)
    replacement = [
        onnx.helper.make_node(
            "Transpose", [source], ["segment_nchw_in"], perm=[0, 3, 1, 2], name="segment_to_nchw"
        ),
        onnx.helper.make_node(
            "ConvTranspose",
            ["segment_nchw_in", "segment_convtranspose_w", bias_name],
            ["segment_nchw_out"],
            name="segment_convtranspose",
            kernel_shape=[2, 2],
            strides=[2, 2],
            pads=[0, 0, 0, 0],
            dilations=[1, 1],
            group=1,
        ),
        onnx.helper.make_node(
            "Transpose", ["segment_nchw_out"], [output], perm=[0, 2, 3, 1], name="segment_to_nhwc"
        ),
    ]

    graph.node.remove(node)
    for offset, new in enumerate(replacement):
        graph.node.insert(index + offset, new)
    graph.initializer.remove(initialisers[weights_name])

    onnx.checker.check_model(model, full_check=True)
    onnx.save(model, ONNX)
    print(f"wrote {ONNX.name}")


def verify() -> None:
    """Step three: the ONNX against the TFLite it came from.

    On real pictures, not only on noise. A rewritten graph can be wrong in ways
    that a synthetic input does not show: this model answers an almost uniform
    zero for anything that is not a person, so comparing on noise alone would
    compare nothing.
    """
    import onnxruntime as ort
    import tensorflow as tf
    from PIL import Image

    interpreter = tf.lite.Interpreter(model_path=str(TFLITE))
    interpreter.allocate_tensors()
    tflite_in = interpreter.get_input_details()[0]
    tflite_out = interpreter.get_output_details()[0]

    if tuple(tflite_in["shape"]) != SHAPE_IN or tuple(tflite_out["shape"]) != SHAPE_OUT:
        raise SystemExit(
            f"the published model's shapes have changed: {tflite_in['shape']} -> "
            f"{tflite_out['shape']}; `segmentation::onnx`'s constants need the same change"
        )

    session = ort.InferenceSession(str(ONNX), providers=["CPUExecutionProvider"])
    worst = 0.0

    for name in TEST_IMAGES:
        path = fetch(TEST_IMAGE_URL.format(name), HERE / name)
        image = Image.open(path).convert("RGB").resize((256, 256), Image.BILINEAR)
        pixels = (np.asarray(image, dtype=np.float32) / 255.0)[None]

        interpreter.set_tensor(tflite_in["index"], pixels)
        interpreter.invoke()
        want = interpreter.get_tensor(tflite_out["index"])
        got = session.run(None, {"input_1": pixels})[0]

        if got.shape != want.shape:
            raise SystemExit(f"{name}: shape {got.shape} is not {want.shape}")

        difference = float(np.abs(got - want).max())
        agreement = float(((got > 0.5) == (want > 0.5)).mean())
        found = float((want > 0.5).mean())
        worst = max(worst, difference)
        print(
            f"{name}: max difference {difference:.6f}, agreement {agreement * 100:.3f}%, "
            f"person pixels {found * 100:.1f}%"
        )

        if found < 0.05:
            raise SystemExit(f"{name}: the model found almost no person, so this proves nothing")
        if agreement < 0.999:
            raise SystemExit(f"{name}: the rewritten graph disagrees about {(1 - agreement) * 100:.2f}% of pixels")

        path.unlink()

    if worst > 1e-3:
        raise SystemExit(f"the rewritten graph differs by {worst}, which is more than rounding")
    print("the ONNX matches the TFLite it came from")


def main() -> None:
    fetch(SOURCE_URL, TFLITE)
    convert()
    replace_the_custom_op()
    verify()
    RAW_ONNX.unlink()

    print()
    print(f"selfie_segmenter.tflite   {digest(TFLITE)}")
    print(f"selfie_segmenter_v1.onnx  {digest(ONNX)}")
    print()
    print("put both in the table in README.md; .gitignore keeps the rest out")


if __name__ == "__main__":
    main()
