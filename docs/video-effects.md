# Camera effects

Background blur and background replacement for a camera in a call, in
`crates/raindrop_video`. Independent of the encryption core: the two crates
share this workspace and its build, and nothing else.

## Why it is here

The effects have to run on all five of the client's targets, and the Flutter
media library exposes **no way to touch a camera frame from Dart at all** — the
method channel has `captureFrame`, `getSources` and the frame cryptor, and
nothing that hands over pixels. So the work has to happen in native code,
reached from the capture pipeline.

Writing it once in Rust, and letting the same cargokit build that already ships
the encryption core carry it, means one segmentation implementation, one model
and one set of tests instead of five. The per-platform native code is then only
a shim that hands over pointers.

This is a scope widening for a repo whose name says crypto. The alternative — a
fourth top-level project — costs a second CI matrix and a second docs wiki and
buys a tidier name; a second cargokit builder package is needed either way.

## What crosses the boundary

**Frames never reach Dart.** The client holds a handle to an `Effects` and the
address of a C function; the platform's capture pipeline calls that function per
frame with the handle as its context, and the planes are rewritten where they
lie.

That matters for three reasons:

- There is no second track and no copy of the picture, so **the frame cryptor
  never notices**. The effects are entirely separate from the end-to-end
  encryption, and could not weaken it even if they were wrong.
- No BGRA-to-I420 round trip, which is the dominant cost in the other obvious
  design (~8ms per frame per core at 1080p).
- The published track's identity never changes, so nothing has to be
  renegotiated when an effect is switched on or off mid-call.

## The three surfaces

The effects are reached through `raindrop_crypto_ffi`, the same library the
encryption core already ships (`Cargo.toml` depends on `raindrop_video`). A
second library would have meant a second cargokit builder, a second codegen and
a second `.so` to keep in step, for two crates that have to be in the app
together anyway.

**`src/api/video.rs` — control, over flutter_rust_bridge.** What Dart calls:

| Function | Does |
|---|---|
| `video_effects_capabilities()` | Whether a model is bundled, and which backend. The UI reads this rather than guessing from the platform |
| `video_effects_process_address()` | The address of the per-frame C function, as an integer |
| `video_effects_create(config)` | Opens effects, returns a handle. **Refuses with `Unsupported` when no model is bundled** |
| `video_effects_update(handle, config)` | Changes the effect under a running camera |
| `video_effects_set_background_file(handle, path)` | Decodes a picture *in Rust*, so a 4K photograph is not 24 MB of Dart list |
| `video_effects_stats(handle)` | Frames, masks, and whether the ladder has stepped down |
| `video_effects_destroy(handle)` | Releases the effects and the segmentation thread |

The handle is a plain `u64`, not an frb opaque object, because it has to travel
through a Dart `int` into platform code that knows nothing about Rust. It
indexes a `static Mutex<HashMap<u64, Effects>>`, and the per-frame path takes it
with **`try_lock`, never `lock`**: the capture thread must not block behind a
configuration change, and a frame left alone for one tick is invisible where a
stalled camera is not.

**`src/c_api.rs` — the hot path, as plain C.** One `#[unsafe(no_mangle)]`
function:

```rust
pub type ProcessI420 = unsafe extern "C" fn(
    context: i64, y: *mut u8, y_stride: i32, u: *mut u8, u_stride: i32,
    v: *mut u8, v_stride: i32, width: i32, height: i32) -> i32;
```

`0` means the frame was processed; every negative value means it was left
*exactly* as it arrived — `-1` bad dimensions, `-2` a frame
`I420FrameMut::new` would not accept, `-3` effects busy or the handle gone,
`-5` the processor panicked (caught with `catch_unwind` in `c_api::guarded`, so
the panic never unwinds out of the `extern "C"` function, which would abort the app).
**A negative return is not an error the caller has to handle**: passing the
frame on untouched is always the right fallback.

Apple's native side reaches this by address, so it holds no Raindrop symbol and
links against nothing of this workspace — it would work just as well against
any other processor.

**`src/jni_api.rs` — the same thing for Android.** Android cannot call an
address: frames arrive in Java, their planes are `ByteBuffer`s, and only JNI can
turn one into a pointer. So the symbol is exported from this library and bound
by name:

```
com.raindrop.video.NativeFrameProcessor.processI420
```

**That Java class name is a contract this workspace owns.** It is deliberately
in a package of its own rather than in the client plugin's, so nothing here
encodes the client's internals; the client declares the class in that package
and calls `System.loadLibrary("raindrop_crypto_ffi")`. Changing the name or the
signature on either side breaks the binding at the first frame, so change both
together.

Each plane is passed as its buffer **plus an offset**: a cropped or scaled I420
buffer is a view whose `position()` is not zero, while `GetDirectBufferAddress`
answers for the whole region. Nothing from the JVM is trusted — a buffer that is
not direct, or too small for the dimensions claimed, is reported (`-4`) and the
frame goes through untouched. `with_env` wraps the body in `catch_unwind`, so a
panic costs one frame rather than the process, and reports `-5`.

This is also why the `jni` dependency is `[target.'cfg(target_os = "android")'
.dependencies]` — it exists for exactly this one function.

## The frame

`frame::I420FrameMut` is the crate's **only `unsafe`**. I420 is what every
camera pipeline Raindrop touches produces: a full-size luma plane and two
half-size chroma planes, each with its own stride that may be wider than the
picture.

Two rules the whole crate depends on:

- **Every access goes through `row` / `row_mut`**, which return a slice exactly
  as wide as the picture. The stride padding belongs to whoever allocated the
  frame; writing into it corrupts memory rather than the image, so it would not
  show up as a bad picture. `stride_padding_is_never_touched` is the test.
- **Chroma planes are half-size rounded *up*.** A 641-wide frame has 321 chroma
  columns, not 320. Every off-by-one in this crate lives in that rounding, which
  is why `odd_dimensions_do_not_panic` covers 1×1, 3×5, 5×3, 7×7, 2×1 and
  641×361.

`new` takes raw pointers and documents what the caller must guarantee;
everything it can check — null planes, zero dimensions, a stride narrower than
its plane — is `Error::BadFrame` rather than trusted. `from_slices` is the safe
constructor the tests use.

## Two clocks

| | What runs | Where |
|---|---|---|
| Every frame | The composite: blur or replace, blended through the mask | The capture thread |
| `mask_hz` times a second | Segmentation | A worker thread |

Deliberately out of step. Segmentation is an order of magnitude dearer than
compositing, and a person does not move far in 60ms, so running it at the frame
rate would spend almost all of the budget for almost no improvement.

**The capture thread never waits for a mask.** It composites against the newest
one that has arrived. A slow segmenter therefore makes the mask lag — which
`mask::SMOOTHING` already covers for — rather than dropping frames.

The request channel holds exactly one square. If the worker is still busy the
offer is declined, which is the normal state under load and not an error: a
queue would mean compositing against masks that are already stale, and under
sustained overload would grow without bound.

**Until the first mask arrives, frames pass through untouched.** The alternative
is blurring a person who has not been found yet, which looks like the camera is
broken. `Stats::masks` is how the UI knows to hold a preview back until the
effect is really working.

## The mask

The model works at its own small size, so a mask arrives much coarser than the
frame. Two things stop that looking wrong:

- **Bilinear upscaling**, sampling at pixel *centres*. Sampling at corners
  shifts the mask by half a source pixel, which at this scale factor is several
  pixels of frame and reads as the blur being offset from the person.
  `a_scaled_mask_stays_centred` asserts the symmetry that only holds if this is
  right.
- **Temporal smoothing** at `SMOOTHING = 0.6`. Without it, a mask recomputed
  every few frames makes the edge visibly crawl. It costs a little lag, which is
  the trade the constant's doc comment records.

One subtlety worth knowing: the blend rounds, and rounding stalls one short —
blending 1 towards 0 at 0.6 gives 0.6, which rounds back to 1 forever. Left
alone a mask never quite reaches full background, so the blur stays a shade off
everywhere it should have faded out completely. `smooth_towards` steps the last
unit by hand.

## Blur

Three passes of a **separable box blur**, not a Gaussian: visually
indistinguishable at these radii, and linear in the radius instead of quadratic,
which is the difference between fitting the per-frame budget and not. Each pass
is a running sum, so a pixel costs one add and one subtract however wide the
window is. Edges clamp to the outermost pixel, which keeps the border from
darkening towards an imaginary black surround.

The radius is a **fraction of the frame's height** (`blur::radius_for`), so the
effect looks the same at every capture resolution — a fixed pixel radius is
heavy at 360p and barely visible at 1080p.

Two details of the implementation are there for speed and are worth not undoing,
since both are measured in [What it actually costs](#what-it-actually-costs):

- **The window mean is a reciprocal multiply, not a division.** At 540p there
  are six million `sum / window` per frame, and an integer division costs an
  order of magnitude more than a multiply. `blur::Reciprocal` is the textbook
  `floor(sum * ceil(2^32 / window) / 2^32)`, and it is **exact** rather than
  approximate over the whole range a box window can produce —
  `the_reciprocal_divides_exactly` checks every value, so the blurred planes
  stay byte-for-byte what the division gave.
- **The vertical pass carries 32 columns at a time.** Walking a single column
  touches a new cache line for every pixel; a block means each line that is
  loaded serves all 32, and the inner loops become contiguous runs the compiler
  can vectorise. `blocking_the_vertical_pass_changes_nothing` pins that against
  a plain column-at-a-time pass, short last block included.

## Background replacement

A replacement image is converted to I420 **once**, at the frame's size, and
cached; a per-frame RGB-to-YUV pass over a whole picture would cost more than
the blur. The cache is keyed by the size it was built for, so a resolution
change rebuilds it and nothing else notices.

The image is scaled to cover and centre-cropped, like CSS `background-size:
cover`, so a replacement of any aspect ratio fills the picture without being
stretched.

Asking to replace the background with no picture chosen is `Error::NoBackground`
rather than a quiet fall back to blur: the user asked for a background and would
otherwise be shown their real room.

## Colour

Effects work directly on I420 — the blur and the composite never leave it, which
is most of why they fit the budget. The one thing that cannot is the segmentation
model, which wants a small square of RGB, so exactly **one** conversion happens
per mask update (not per frame) over that square rather than the whole picture.
BT.601 limited range throughout, which is what a webcam produces.

## The degradation ladder

In the crate, not the UI, because only here is the real cost known and the
decision has to be made inside the frame loop.

| Step | Gives up |
|---|---|
| `HalfMaskRate` | Segmentation at half the configured rate |
| `CoarseBlur` | Half rate, and the blur computed at quarter resolution |
| `Off` | The effect entirely, reported so the UI can say so |

The order gives up the **picture before the motion**. Dropping frames is never
one of the steps.

It takes `Budget::RUN` (30) consecutive frames over *twice* the budget, and any
frame inside budget resets the count — a first frame touching cold caches, or
one scheduling hiccup, must not permanently turn the effect off.
`one_slow_frame_does_not_degrade_anything` is that test.

### What it actually costs

Measured on an Apple-silicon Mac, blur at `Config::default()`, timing
`Effects::process` on the calling thread at 24 fps with the segmentation worker
running beside it:

| Capture | p50 | p95 | Ladder |
|---|---|---|---|
| 640×360 | 2.5 ms | 3.8 ms | never steps |
| 960×540 (the default) | 5.7 ms | 8.2 ms | never steps |
| 1280×720 | 12.5 ms | 14.0 ms | never steps |

`EffectKind::None` is ~300 ns, which is the frame boundary and nothing else.

Those numbers are **after** two changes to `blur.rs` that were worth making
precisely because the ladder was stepping all the way down at 720p before them:
the per-pixel `sum / window` became a reciprocal multiply (six million integer
divisions a frame at 540p, and a division costs an order of magnitude more than
a multiply), and the vertical pass now carries 32 columns at a time, because
walking one column touches a fresh cache line for every pixel. Together they
took 540p from 7.8 ms to 5.7 ms and 720p from 14.6 ms — degrading to no effect
at all — to 12.5 ms, which holds.

A phone several times slower than this will step the ladder down at 540p, which
is what the ladder is for. If that turns out to be the common case rather than
the exception, the next move is blurring a half-resolution copy and upsampling:
the blur is six passes over the planes and the composite is one, so that is a
roughly 4× saving on the expensive part for a difference this radius hides.

## Segmentation

`segmentation::Segmenter` is the seam, for two reasons. The pixel work is most
of the code and all of the per-frame cost, and none of it should know what
produced the mask. And the runtime is the part most likely to be swapped: a
pure-Rust engine is what makes one cargokit build work on all five targets,
while a platform-native or accelerated backend may later beat it on some of
them — and measuring that is only possible if both sit behind the same call.

A segmenter runs on the worker thread, so it may take milliseconds, and must not
panic. An error is a mask that did not arrive, which the pipeline survives by
keeping the previous one: strictly better than a blank mask, which would un-blur
the background for a frame.

Two implementations:

**`onnx::OnnxSegmenter`** is the real one: an ONNX model run by `tract`. Pure
Rust, which is the whole reason for that choice — the one cargokit build has to
produce this crate for five targets with no toolchain of its own, and a runtime
with a C++ core (ONNX Runtime, TensorFlow Lite) would need linking solved
separately on each. The input and output shapes are **fixed as named constants**
and the model is checked against them at load, because a model of an unexpected
shape should be refused when it can be reported rather than produce a quietly
wrong mask on every frame.

**`segmentation::CentreOvalSegmenter`** marks a circle in the middle of the
frame as foreground. Not a mock — a real, deterministic segmenter, and what lets
every pixel path in the crate be tested without an inference runtime or a model
file in the way. The tests assert on a shape they chose, so a regression in the
pixel work shows up as a wrong picture rather than as a worse mask.

### The model

`models/selfie_segmenter_v1.onnx` — MediaPipe Selfie Segmentation (general),
Apache-2.0, about 440 KB, `include_bytes!`d into the binary. `models/README.md`
has the shapes, the hashes and the provenance; `models/convert.py` rebuilds it
from Google's published TensorFlow Lite file and **verifies the result against
that file** on real photographs before writing it. Read that README before
touching either, because the conversion has two steps nobody would guess: ONNX
only gained `HardSwish` at opset 14, and MediaPipe's fused transpose convolution
is a TFLite *custom* op that has to be rewritten as standard ONNX by hand.

A new model is a **new filename**, with a new `MODEL_FILE` and new
`bundled_model` wiring — never an edit in place, the same rule the encryption
core's byte formats follow.

**It is still conditional, on purpose.** A checkout without the file has to
build, so:

- `build.rs` sets `cfg(bundled_model)` only when it sees the file, and
  `OnnxSegmenter::bundled` does not exist otherwise — nothing tries to
  `include_bytes!` something missing.
- `onnx::best()` then returns `CentreOvalSegmenter`, so the crate can still
  composite and every pixel test still runs.
- **But the bridge refuses.** `video_effects_create` returns `Unsupported` when
  `onnx::model_bundled()` is false and `video_effects_capabilities()` reports
  `available: false`, so the client offers no effect at all rather than an oval
  where a person should be. The fallback is for this crate's tests, not for
  shipping — which is why the UI asks the native side instead of branching on
  the platform.
- `Effects::backend()` says which one is in use, and
  `the_build_says_which_segmenter_it_has` asserts a build never claims one and
  runs the other.
- The four `#[cfg(bundled_model)]` tests skip themselves — the same pattern as
  the client's E2EE integration tests, which run only when
  `RAINDROP_TEST_SERVER` names a server.

Those four are the point of the arrangement: they are what answered the question
the model card could not, namely whether the shapes this crate pins are the
shapes the real file has. They are.

## Tests

`cargo test -p raindrop_video` — 27 tests in `tests/effects.rs`, four of which
run only with the segmentation model present, plus two unit tests in `blur.rs`.
They cover the frame boundary (stride padding, odd dimensions, refusals), blur
(background variance drops, foreground variance does not), replacement (the
right pixels, and the refusals), the mask (centring, soft edges, smoothing,
convergence, a resolution change), the ladder (each step in order, and that one
slow frame does not trigger it), colour round-tripping, and determinism.

The two in `blur.rs` are there because that file has the only arithmetic in the
crate that is clever rather than obvious. `the_reciprocal_divides_exactly`
checks the reciprocal multiply against the division it replaces over its
*entire* input domain — every window a radius can produce, every sum that
window can hold — and `blocking_the_vertical_pass_changes_nothing` checks the
cache-blocked pass against a plain column-at-a-time one, including widths that
leave a short last block.

Two test doubles carry most of it:

- **A hand-wound clock** whose every *read* advances it by a set step.
  `Effects::process` reads it once at the start of a frame and once at the end,
  so the step is exactly how long that frame appears to have taken — which is
  how the budget is driven to any value with no real waiting at all.
- **Segmenters that answer in known ways**: all-background (so a composite's
  effect is visible everywhere), and never-finds (for the "no mask yet" path).

## Related

- [Architecture overview](architecture-overview.md)
- [Flutter bridge](flutter-bridge.md) — how the client reaches this workspace
- The client's [`docs/voice.md`](../../RaindropClient/docs/voice.md) — the call
  this is for, and the camera's place in it
