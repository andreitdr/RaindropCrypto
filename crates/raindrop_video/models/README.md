# The segmentation model

`raindrop_video` needs one model: something that says, per pixel, whether it is
a person. Nothing else in the crate depends on which one — see
[Camera effects](../../../docs/video-effects.md#segmentation) for the seam.

`selfie_segmenter_v1.onnx` is committed here, so `build.rs` sets
`cfg(bundled_model)`, `OnnxSegmenter::bundled` exists and `onnx::best()` returns
it. A checkout *without* the file still builds: the crate falls back to
`CentreOvalSegmenter` and four tests skip themselves. That fallback is for the
crate's own sake, not for shipping — the Flutter bridge refuses to create
effects at all when no model is bundled, because an oval where a person should
be is worse than a plain camera.

| | |
|---|---|
| File | `selfie_segmenter_v1.onnx` |
| Model | MediaPipe Selfie Segmentation (general) |
| Licence | Apache-2.0 |
| Input | `input_1`, `1 × 256 × 256 × 3` float32, NHWC, RGB, each channel scaled to 0..1 |
| Output | `activation_10`, `1 × 256 × 256 × 1` float32, a sigmoid confidence that the pixel is a person |
| Opset | 17 |
| Size | ~440 KB |

Those shapes are what `segmentation::onnx` pins, as named constants, and they
are checked against the published TensorFlow Lite file every time
[`convert.py`](convert.py) runs. If a future model disagrees, correct the
constants rather than reshaping around them, and run
`cargo test -p raindrop_video`, which checks them against the real file.

## Rebuilding it

Google publishes this model as TensorFlow Lite only, and the conversion needs
two steps that are not obvious. Both are in [`convert.py`](convert.py), which is
committed for exactly that reason: it fetches the published file, converts it,
rewrites the one operator tf2onnx cannot, and then **checks the result against
the TensorFlow Lite model it came from** on MediaPipe's own test photographs.

```bash
python3 -m venv venv
./venv/bin/pip install 'tensorflow==2.17.1' 'tf2onnx==1.16.1' onnx \
    'tf-keras==2.17.0' onnxruntime 'protobuf==4.25.5' pillow
./venv/bin/python convert.py
```

`.gitignore` keeps everything the script fetches or builds on the way out of the
repository; only the ONNX is committed.

Four things that cost time to find out, so nobody pays for them twice:

- **Opset 17, not 13.** ONNX only gained `HardSwish` at opset 14, and this model
  has eleven of them. At 13 the conversion "succeeds" and produces a model that
  cannot run.
- **One operator has to be rewritten by hand.** `TFL_Convolution2DTransposeBias`
  is a TFLite *custom* op — MediaPipe's fused transpose convolution and bias —
  which tf2onnx leaves in the graph under its TFLite name. Neither tract nor
  onnxruntime will execute that. `convert.py` replaces it with the standard
  `ConvTranspose` it is; the docstring explains how its attributes are derived.
- **tf2onnx needs TensorFlow installed even for `--tflite`**, and a Python that
  current TensorFlow is actually built for. On the reference machine, Xcode's
  Python 3.9 with TensorFlow 2.20 stalls inside TensorFlow's own locking
  (`[mutex.cc : 452] RAW: Lock blocking`) and never writes a file; Homebrew's
  `python@3.12` with the pins above takes about a second. The TensorFlow-free
  `tflite2onnx` cannot read this model at all (`HARD_SWISH`, and no float16),
  and neither can `tract-tflite` (it has no `DEQUANTIZE` for float16 weights) —
  which is why this is an ONNX file and not the TFLite one.
- **The result is not byte-reproducible.** tf2onnx's output differs run to run,
  so the hash below identifies the committed file rather than being a target to
  reproduce. What *is* reproducible is the behaviour: `convert.py` fails unless
  the rewritten graph agrees with the TensorFlow Lite model to within 1e-3 and
  on 99.9% of pixels either side of 0.5.

| File | SHA-256 |
|---|---|
| `selfie_segmenter.tflite` (source, not committed) | `191ac9529ae506ee0beefa6b2c945a172dab9d07d1e802a290a4e4038226658b` (fetched 2026-10-09) |
| `selfie_segmenter_v1.onnx` (committed) | `df82b0aca8cdd773033b95f2c36ab5091580da193f239ea70de9bf93fc9d6e25` |

The source hash is recorded although the file is not kept: `latest/` in that URL
is a moving target, and a later reader needs to be able to tell whether the file
they get is the one this ONNX came from.

## Why it is committed rather than downloaded or shipped as an asset

- **Committed, not downloaded at build time.** A build that reaches the network
  is a build that breaks when someone else's bucket moves, and a model fetched
  at build time is one nobody has checked.
- **`include_bytes!`, not a Flutter asset.** There is then no per-platform asset
  path, no `rootBundle` on five targets, and no file to go missing at runtime.
  A few hundred kilobytes in the binary is nothing beside OpenMLS and SQLCipher.
- **A new model is a new filename**, with a new `MODEL_FILE` and a new
  `bundled_model` wiring — never an edit in place. Same rule as the encryption
  core's byte formats: a new version is a new context.
