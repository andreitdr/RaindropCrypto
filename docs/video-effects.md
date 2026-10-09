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

**`CentreOvalSegmenter` is the only one implemented so far.** It marks a circle
in the middle of the frame as foreground. Not a mock — it is a real,
deterministic segmenter, and it is what lets every pixel path in the crate be
tested without an inference runtime or a model file in the way. The tests assert
on a shape they chose, so a regression in the pixel work shows up as a wrong
picture rather than as a worse mask.

**Still to come:** a real person segmenter. See
[roadmap](roadmap.md) — it needs a model file chosen, licensed and committed,
and an inference runtime added to this crate's dependencies.

## Tests

`cargo test -p raindrop_video` — 22 tests in `tests/effects.rs`, covering the
frame boundary (stride padding, odd dimensions, refusals), blur (background
variance drops, foreground variance does not), replacement (the right pixels,
and the refusals), the mask (centring, soft edges, smoothing, convergence,
a resolution change), the ladder (each step in order, and that one slow frame
does not trigger it), colour round-tripping, and determinism.

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
