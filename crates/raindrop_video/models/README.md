# The segmentation model

`raindrop_video` needs one model: something that says, per pixel, whether it is
a person. Nothing else in the crate depends on which one — see
[Camera effects](../../../docs/video-effects.md#segmentation) for the seam.

**No model is committed yet.** Until one is, `build.rs` leaves
`cfg(bundled_model)` off, `OnnxSegmenter::bundled` does not exist, and the crate
falls back to `CentreOvalSegmenter`. Everything builds and every test passes
without it; the real segmenter appears the moment the file is dropped in here.

## What to put here

| | |
|---|---|
| Filename | `selfie_segmenter_v1.onnx` |
| Model | MediaPipe Selfie Segmentation (general) |
| Licence | Apache-2.0 |
| Input | `1 × 256 × 256 × 3` float32, NHWC, RGB, each channel scaled to 0..1 |
| Output | `1 × 256 × 256 × 1` float32, a sigmoid confidence that the pixel is a person |

Those shapes are what `segmentation::onnx` expects, as named constants. If the
model you fetch disagrees, correct the constants rather than reshaping around
them — and run `cargo test -p raindrop_video` with the model present, which
checks them.

## Getting it

Google publishes the model as TensorFlow Lite, so there are two steps. Run them
from this folder.

```bash
curl -L -o selfie_segmenter.tflite \
  https://storage.googleapis.com/mediapipe-models/image_segmenter/selfie_segmenter/float16/latest/selfie_segmenter.tflite
```

```bash
python3 -m pip install tf2onnx onnx && \
  python3 -m tf2onnx.convert --opset 13 \
    --tflite selfie_segmenter.tflite --output selfie_segmenter_v1.onnx
```

Then record what you actually got, so a later reader can tell whether the file
has changed under them:

```bash
shasum -a 256 selfie_segmenter.tflite selfie_segmenter_v1.onnx
```

Write both hashes into the table below, commit `selfie_segmenter_v1.onnx`, and
delete the `.tflite` — the ONNX file is the artefact, and keeping both invites
them to drift apart.

| File | SHA-256 |
|---|---|
| `selfie_segmenter.tflite` (source, not committed) | _record it here_ |
| `selfie_segmenter_v1.onnx` (committed) | _record it here_ |

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
