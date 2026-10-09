//! What the effects do to a picture.
//!
//! The segmenter under test is [`CentreOvalSegmenter`], a real deterministic
//! one: the person is a circle in the middle of the frame. So every assertion
//! here is about the *pixel* work — the blur, the composite, the mask stretch,
//! the smoothing, the degradation ladder — and a regression in any of it shows
//! up as a wrong picture rather than as a worse mask.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use raindrop_video::frame::{I420FrameMut, Plane};
use raindrop_video::mask::Mask;
use raindrop_video::pipeline::{Degradation, TimeSource};
use raindrop_video::replace::Background;
use raindrop_video::segmentation::{CentreOvalSegmenter, Segmenter};
use raindrop_video::{Config, EffectKind, Effects, Error};

// ── A frame to work on ───────────────────────────────────────────────────────

/// Three planes with their own strides, so padding is always in play.
struct Picture {
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
    y_stride: usize,
    c_stride: usize,
    width: usize,
    height: usize,
}

impl Picture {
    /// A frame whose background is visibly textured and whose middle is flat,
    /// so a blur has something to destroy and the foreground has something to
    /// preserve. `pad` is how much stride padding each plane carries.
    fn new(width: usize, height: usize, pad: usize) -> Self {
        let chroma_width = width.div_ceil(2);
        let chroma_height = height.div_ceil(2);
        let y_stride = width + pad;
        let c_stride = chroma_width + pad;

        let mut picture = Self {
            y: vec![0xAA; y_stride * height],
            u: vec![0xAA; c_stride * chroma_height],
            v: vec![0xAA; c_stride * chroma_height],
            y_stride,
            c_stride,
            width,
            height,
        };

        // A hard checkerboard: maximal local variance, so "did the blur run"
        // is a question about variance rather than about any one pixel.
        for y in 0..height {
            for x in 0..width {
                picture.y[y * y_stride + x] = if (x / 2 + y / 2) % 2 == 0 { 235 } else { 16 };
            }
        }
        for y in 0..chroma_height {
            for x in 0..chroma_width {
                picture.u[y * c_stride + x] = if (x + y) % 2 == 0 { 200 } else { 60 };
                picture.v[y * c_stride + x] = 128;
            }
        }

        picture
    }

    fn frame(&mut self) -> I420FrameMut<'_> {
        I420FrameMut::from_slices(
            &mut self.y,
            self.y_stride,
            &mut self.u,
            self.c_stride,
            &mut self.v,
            self.c_stride,
            self.width,
            self.height,
        )
        .expect("the planes describe a frame")
    }

    fn luma(&self, x: usize, y: usize) -> u8 {
        self.y[y * self.y_stride + x]
    }

    /// Variance of the luma in a box, which is what a blur flattens.
    fn variance(&self, left: usize, top: usize, size: usize) -> f64 {
        let mut values = Vec::with_capacity(size * size);
        for y in top..(top + size).min(self.height) {
            for x in left..(left + size).min(self.width) {
                values.push(f64::from(self.luma(x, y)));
            }
        }

        let mean = values.iter().sum::<f64>() / values.len() as f64;
        values.iter().map(|value| (value - mean).powi(2)).sum::<f64>() / values.len() as f64
    }
}

// ── Driving the effects deterministically ────────────────────────────────────

/// A clock the test winds by hand, so the mask rate and the degradation ladder
/// are exercised without any real waiting.
///
/// Every *read* advances it by [`Self::set_step`]. `Effects::process` reads the
/// clock once at the start of a frame and once at the end, so the step is
/// exactly how long that frame appears to have taken — which is how the
/// budget can be driven to any value deterministically. [`Self::advance`] moves
/// it between frames, for the mask clock.
#[derive(Clone, Default)]
struct Hand {
    now: Arc<Mutex<Duration>>,
    step: Arc<Mutex<Duration>>,
}

impl Hand {
    fn advance(&self, by: Duration) {
        *self.now.lock().unwrap() += by;
    }

    /// How long each frame appears to take.
    fn set_step(&self, step: Duration) {
        *self.step.lock().unwrap() = step;
    }
}

impl TimeSource for Hand {
    fn now(&self) -> Duration {
        let mut now = self.now.lock().unwrap();
        let reading = *now;
        *now += *self.step.lock().unwrap();
        reading
    }
}

/// A segmenter that always claims the whole picture is background, so a
/// composite's effect is visible everywhere rather than only at the edges.
struct AllBackground(usize);

impl Segmenter for AllBackground {
    fn name(&self) -> &'static str {
        "all-background"
    }

    fn input_size(&self) -> usize {
        self.0
    }

    fn segment(&mut self, _rgb: &[u8]) -> Result<Mask, Error> {
        Ok(Mask::new(self.0, self.0))
    }
}

/// A segmenter that never answers, for the "no mask yet" path.
struct NeverFinds;

impl Segmenter for NeverFinds {
    fn name(&self) -> &'static str {
        "never-finds"
    }

    fn input_size(&self) -> usize {
        16
    }

    fn segment(&mut self, _rgb: &[u8]) -> Result<Mask, Error> {
        Err(Error::Segmentation("deliberately"))
    }
}

/// Runs frames until a mask has arrived and been composited, or gives up.
///
/// The worker is a real thread, so a mask is not ready on the first frame; the
/// pipeline is built not to wait for one, which is exactly why a test has to.
fn run_until_warm(effects: &mut Effects, picture: &mut Picture, hand: &Hand) -> bool {
    for _ in 0..200 {
        let mut frame = picture.frame();
        effects.process(&mut frame).expect("a frame is processed");
        if effects.stats().masks > 0 {
            // One more frame, so the mask that arrived is actually composited.
            let mut frame = picture.frame();
            effects.process(&mut frame).expect("a frame is processed");
            return true;
        }
        hand.advance(Duration::from_millis(16));
        std::thread::sleep(Duration::from_millis(2));
    }

    false
}

fn effects_with(kind: EffectKind, segmenter: Box<dyn Segmenter>, hand: &Hand) -> Effects {
    Effects::with_parts(
        Config {
            kind,
            mask_hz: 60.0,
            ..Config::default()
        },
        segmenter,
        Box::new(hand.clone()),
    )
    .expect("the effects start")
}

// ── The frame boundary ───────────────────────────────────────────────────────

#[test]
fn stride_padding_is_never_touched() {
    let mut picture = Picture::new(64, 48, 7);
    let padding_before: Vec<u8> = picture
        .y
        .chunks(picture.y_stride)
        .flat_map(|row| row[picture.width..].to_vec())
        .collect();

    let hand = Hand::default();
    let mut effects = effects_with(EffectKind::Blur, Box::new(AllBackground(16)), &hand);
    assert!(run_until_warm(&mut effects, &mut picture, &hand));

    let padding_after: Vec<u8> = picture
        .y
        .chunks(picture.y_stride)
        .flat_map(|row| row[picture.width..].to_vec())
        .collect();

    // The padding belongs to whoever allocated the frame. Writing into it is
    // the failure mode a stride-unaware implementation has, and it corrupts
    // memory rather than the picture, so it would not show up as a bad image.
    assert_eq!(padding_before, padding_after, "the blur wrote into the stride padding");
}

#[test]
fn a_frame_with_no_pixels_is_refused() {
    let mut y = [0u8; 4];
    let mut u = [0u8; 4];
    let mut v = [0u8; 4];

    assert!(matches!(
        I420FrameMut::from_slices(&mut y, 1, &mut u, 1, &mut v, 1, 0, 4),
        Err(Error::BadFrame(_))
    ));
}

#[test]
fn a_stride_narrower_than_its_plane_is_refused() {
    let mut y = vec![0u8; 64];
    let mut u = vec![0u8; 64];
    let mut v = vec![0u8; 64];

    assert!(matches!(
        I420FrameMut::from_slices(&mut y, 4, &mut u, 4, &mut v, 4, 8, 4),
        Err(Error::BadFrame(_))
    ));
}

#[test]
fn odd_dimensions_do_not_panic() {
    // I420's chroma planes are half-size rounded *up*, and every off-by-one in
    // this crate lives in that rounding.
    for (width, height) in [(1, 1), (3, 5), (5, 3), (7, 7), (641, 361), (2, 1)] {
        let mut picture = Picture::new(width, height, 3);
        let hand = Hand::default();
        let mut effects = effects_with(EffectKind::Blur, Box::new(AllBackground(8)), &hand);

        for _ in 0..5 {
            let mut frame = picture.frame();
            effects
                .process(&mut frame)
                .unwrap_or_else(|e| panic!("{width}x{height}: {e}"));
            hand.advance(Duration::from_millis(16));
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

#[test]
fn chroma_planes_round_up() {
    let mut picture = Picture::new(641, 361, 0);
    let frame = picture.frame();

    assert_eq!(frame.chroma_width(), 321);
    assert_eq!(frame.chroma_height(), 181);
    assert_eq!(frame.plane_width(Plane::U), 321);
    assert_eq!(frame.plane_height(Plane::V), 181);
}

// ── Blur ─────────────────────────────────────────────────────────────────────

#[test]
fn blur_flattens_the_background_and_leaves_the_foreground() {
    let mut picture = Picture::new(128, 128, 5);
    let background_before = picture.variance(4, 4, 24);
    let foreground_before = picture.variance(56, 56, 16);

    let hand = Hand::default();
    let mut effects = effects_with(EffectKind::Blur, Box::new(CentreOvalSegmenter::new(64)), &hand);
    assert!(run_until_warm(&mut effects, &mut picture, &hand));

    let background_after = picture.variance(4, 4, 24);
    let foreground_after = picture.variance(56, 56, 16);

    assert!(
        background_after < background_before * 0.25,
        "the corner should be blurred: {background_before} -> {background_after}"
    );
    assert!(
        foreground_after > foreground_before * 0.9,
        "the middle is the person and should be untouched: {foreground_before} -> {foreground_after}"
    );
}

#[test]
fn no_effect_leaves_every_byte_alone() {
    let mut picture = Picture::new(64, 64, 4);
    let before = (picture.y.clone(), picture.u.clone(), picture.v.clone());

    let hand = Hand::default();
    let mut effects = effects_with(EffectKind::None, Box::new(AllBackground(16)), &hand);

    for _ in 0..20 {
        let mut frame = picture.frame();
        effects.process(&mut frame).expect("a frame is processed");
        hand.advance(Duration::from_millis(16));
    }

    assert_eq!((picture.y.clone(), picture.u.clone(), picture.v.clone()), before);
    assert_eq!(effects.stats().masks, 0, "no effect should run no segmentation at all");
    assert_eq!(effects.backend(), "none");
}

#[test]
fn frames_pass_through_until_a_mask_arrives() {
    let mut picture = Picture::new(64, 64, 0);
    let before = picture.y.clone();

    let hand = Hand::default();
    let mut effects = effects_with(EffectKind::Blur, Box::new(NeverFinds), &hand);

    for _ in 0..30 {
        let mut frame = picture.frame();
        effects.process(&mut frame).expect("a frame is processed");
        hand.advance(Duration::from_millis(16));
        std::thread::sleep(Duration::from_millis(1));
    }

    // A segmenter that cannot find anybody must not blur the whole picture —
    // the effect is simply not applied until there is something to apply it to.
    assert_eq!(picture.y, before);
    assert_eq!(effects.stats().masks, 0);
}

// ── Background replacement ───────────────────────────────────────────────────

fn flat_background(width: usize, height: usize, rgb: (u8, u8, u8)) -> Background {
    let mut pixels = Vec::with_capacity(width * height * 3);
    for _ in 0..width * height {
        pixels.extend_from_slice(&[rgb.0, rgb.1, rgb.2]);
    }

    Background { width, height, pixels }
}

#[test]
fn replace_puts_the_picture_behind_the_person() {
    let mut picture = Picture::new(96, 96, 3);

    let hand = Hand::default();
    let mut effects = Effects::with_parts(
        Config {
            kind: EffectKind::Replace,
            mask_hz: 60.0,
            ..Config::default()
        },
        Box::new(AllBackground(16)),
        Box::new(hand.clone()),
    )
    .expect("the effects start");

    // Pure red, so what lands in the planes is checkable by hand.
    effects
        .set_background(flat_background(8, 8, (255, 0, 0)))
        .expect("the background is usable");
    assert!(run_until_warm(&mut effects, &mut picture, &hand));

    let (expected_y, _, _) = raindrop_video::convert::rgb_to_yuv(255, 0, 0);

    // Every pixel is background for this segmenter, so every pixel is the
    // replacement. Allowing 1 is the rounding in the 8-bit blend.
    for (x, y) in [(0, 0), (48, 48), (95, 95), (10, 80)] {
        let got = picture.luma(x, y);
        assert!(
            got.abs_diff(expected_y) <= 1,
            "({x},{y}) should be the replacement: expected ~{expected_y}, got {got}"
        );
    }
}

#[test]
fn replace_without_a_picture_says_so() {
    let mut picture = Picture::new(32, 32, 0);
    let hand = Hand::default();
    let mut effects = effects_with(EffectKind::Replace, Box::new(AllBackground(16)), &hand);

    let mut frame = picture.frame();
    let error = effects.process(&mut frame).unwrap_err();

    // Quietly blurring instead would be worse: the user asked for a background
    // and would be shown their real room.
    assert_eq!(error, Error::NoBackground);
}

#[test]
fn a_background_smaller_than_it_claims_is_refused() {
    let hand = Hand::default();
    let mut effects = effects_with(EffectKind::Replace, Box::new(AllBackground(16)), &hand);

    let error = effects
        .set_background(Background {
            width: 64,
            height: 64,
            pixels: vec![0; 10],
        })
        .unwrap_err();

    assert!(matches!(error, Error::BadBackground(_)));
}

#[test]
fn switching_effect_keeps_the_camera_and_the_mask() {
    let mut picture = Picture::new(64, 64, 2);
    let hand = Hand::default();
    let mut effects = effects_with(EffectKind::Blur, Box::new(AllBackground(16)), &hand);
    assert!(run_until_warm(&mut effects, &mut picture, &hand));

    let masks = effects.stats().masks;
    effects
        .set_config(Config {
            kind: EffectKind::Replace,
            mask_hz: 60.0,
            ..Config::default()
        })
        .expect("the effect changes");
    effects
        .set_background(flat_background(4, 4, (0, 0, 255)))
        .expect("the background is usable");

    let mut frame = picture.frame();
    effects.process(&mut frame).expect("a frame is processed");

    // The expensive part is the mask, and it is the same mask either way —
    // which is what lets the pre-join sheet preview both without restarting
    // the camera.
    assert!(effects.stats().masks >= masks);
}

#[test]
fn turning_the_effect_off_stops_segmenting() {
    let mut picture = Picture::new(64, 64, 0);
    let hand = Hand::default();
    let mut effects = effects_with(EffectKind::Blur, Box::new(AllBackground(16)), &hand);
    assert!(run_until_warm(&mut effects, &mut picture, &hand));

    effects
        .set_config(Config {
            kind: EffectKind::None,
            ..Config::default()
        })
        .expect("the effect changes");

    let settled = effects.stats().masks;
    let before = picture.y.clone();

    for _ in 0..20 {
        let mut frame = picture.frame();
        effects.process(&mut frame).expect("a frame is processed");
        hand.advance(Duration::from_millis(16));
        std::thread::sleep(Duration::from_millis(1));
    }

    assert_eq!(
        effects.stats().masks,
        settled,
        "a stopped worker should segment nothing"
    );
    assert_eq!(picture.y, before);
}

// ── The mask ─────────────────────────────────────────────────────────────────

#[test]
fn a_scaled_mask_stays_centred() {
    // Sampling at pixel corners instead of centres shifts the mask by half a
    // source pixel, which at this scale factor is several pixels of frame and
    // reads as the blur being offset from the person.
    // The middle 2x2 of a 4x4 mask, written as (row, column) so the shape is
    // readable.
    let mut small = Mask::new(4, 4);
    for (row, column) in [(1, 1), (1, 2), (2, 1), (2, 2)] {
        small.alpha[row * 4 + column] = 255;
    }

    let big = small.scaled_to(64, 64);

    assert_eq!(big.at(32, 32), 255, "the middle should still be the middle");
    assert_eq!(big.at(0, 0), 0);
    assert_eq!(big.at(63, 63), 0);

    // Symmetric about both axes, which only holds if the sampling is centred.
    for offset in [8, 16, 24] {
        assert_eq!(
            big.at(32 - offset, 32),
            big.at(31 + offset, 32),
            "asymmetric at ±{offset} horizontally"
        );
        assert_eq!(
            big.at(32, 32 - offset),
            big.at(32, 31 + offset),
            "asymmetric at ±{offset} vertically"
        );
    }
}

#[test]
fn a_scaled_mask_has_a_soft_edge() {
    let mut small = Mask::new(8, 8);
    for y in 2..6 {
        for x in 2..6 {
            small.alpha[y * 8 + x] = 255;
        }
    }

    let big = small.scaled_to(64, 64);

    // Bilinear, not nearest: a staircase edge is what makes a blur look cut out.
    assert!(
        big.alpha.iter().any(|&a| a > 0 && a < 255),
        "the edge should be a gradient, not a step"
    );
}

#[test]
fn smoothing_moves_towards_the_new_mask_without_jumping_to_it() {
    let mut current = Mask::opaque(4, 4);
    let next = Mask::new(4, 4);

    current.smooth_towards(&next, 0.6);

    // 0.6 of 255 — most of the old mask survives, which is what stops the edge
    // crawling when the mask updates slower than the frame rate.
    assert_eq!(current.at(0, 0), 153);

    for _ in 0..40 {
        current.smooth_towards(&next, 0.6);
    }
    assert_eq!(current.at(0, 0), 0, "it should converge, not stall short");
}

#[test]
fn a_mask_of_a_different_size_replaces_rather_than_blends() {
    let mut current = Mask::opaque(4, 4);
    let next = Mask::new(8, 8);

    current.smooth_towards(&next, 0.6);

    // A resolution change has no sensible previous mask to carry over.
    assert_eq!(current.width, 8);
    assert_eq!(current.at(0, 0), 0);
}

// ── The degradation ladder ───────────────────────────────────────────────────

#[test]
fn the_ladder_steps_down_under_sustained_overload_and_reports_it() {
    let mut picture = Picture::new(64, 64, 0);
    let hand = Hand::default();

    let mut effects = Effects::with_parts(
        Config {
            kind: EffectKind::Blur,
            mask_hz: 60.0,
            frame_budget: Duration::from_millis(5),
            ..Config::default()
        },
        Box::new(AllBackground(16)),
        Box::new(hand.clone()),
    )
    .expect("the effects start");

    assert_eq!(effects.stats().level, Degradation::None);

    // Every frame "takes" 50ms against a 5ms budget. The clock is the test's,
    // so this is instant.
    hand.set_step(Duration::from_millis(50));

    let mut seen = vec![Degradation::None];
    for _ in 0..(4 * 31) {
        let mut frame = picture.frame();
        effects.process(&mut frame).expect("a frame is processed");

        let level = effects.stats().level;
        if Some(&level) != seen.last() {
            seen.push(level);
        }
    }

    assert_eq!(
        seen,
        vec![
            Degradation::None,
            Degradation::HalfMaskRate,
            Degradation::CoarseBlur,
            Degradation::Off
        ],
        "the ladder should give up the picture before the motion, in order"
    );

    let stats = effects.stats();
    assert!(stats.degraded, "the UI has to be able to say so");
    assert_eq!(stats.degradations, 3);
}

#[test]
fn one_slow_frame_does_not_degrade_anything() {
    let mut picture = Picture::new(64, 64, 0);
    let hand = Hand::default();

    let mut effects = Effects::with_parts(
        Config {
            kind: EffectKind::Blur,
            frame_budget: Duration::from_millis(5),
            ..Config::default()
        },
        Box::new(AllBackground(16)),
        Box::new(hand.clone()),
    )
    .expect("the effects start");

    // A first frame touching cold caches, or one scheduling hiccup, must not
    // permanently turn the effect off.
    for index in 0..60 {
        hand.set_step(if index % 10 == 0 {
            Duration::from_millis(80)
        } else {
            Duration::from_millis(1)
        });

        let mut frame = picture.frame();
        effects.process(&mut frame).expect("a frame is processed");
    }

    assert_eq!(effects.stats().level, Degradation::None);
    assert!(!effects.stats().degraded);
}

#[test]
fn the_effect_switched_off_by_the_ladder_leaves_frames_alone() {
    let mut picture = Picture::new(64, 64, 0);
    let hand = Hand::default();

    let mut effects = Effects::with_parts(
        Config {
            kind: EffectKind::Blur,
            mask_hz: 60.0,
            frame_budget: Duration::from_millis(1),
            ..Config::default()
        },
        Box::new(AllBackground(16)),
        Box::new(hand.clone()),
    )
    .expect("the effects start");

    hand.set_step(Duration::from_millis(50));
    for _ in 0..(4 * 31) {
        let mut frame = picture.frame();
        let _ = effects.process(&mut frame);
    }
    assert_eq!(effects.stats().level, Degradation::Off);

    let before = picture.y.clone();
    for _ in 0..10 {
        let mut frame = picture.frame();
        effects.process(&mut frame).expect("a frame is processed");
    }

    assert_eq!(
        picture.y, before,
        "a switched-off effect should cost nothing and change nothing"
    );
}

// ── Colour ───────────────────────────────────────────────────────────────────

#[test]
fn colour_conversion_round_trips_within_tolerance() {
    // BT.601 limited range is lossy in both directions; what matters is that a
    // replacement background does not come out visibly wrong.
    for rgb in [
        (0, 0, 0),
        (255, 255, 255),
        (255, 0, 0),
        (0, 255, 0),
        (0, 0, 255),
        (128, 64, 192),
    ] {
        let (y, u, v) = raindrop_video::convert::rgb_to_yuv(rgb.0, rgb.1, rgb.2);
        let back = raindrop_video::convert::yuv_to_rgb(y, u, v);

        for (channel, (a, b)) in [(back.0, rgb.0), (back.1, rgb.1), (back.2, rgb.2)].iter().enumerate() {
            assert!(
                a.abs_diff(*b) <= 4,
                "channel {channel} of {rgb:?} came back as {back:?}"
            );
        }
    }
}

// ── Determinism ──────────────────────────────────────────────────────────────

#[test]
fn the_same_frame_and_mask_give_the_same_pixels() {
    let run = || {
        let mut picture = Picture::new(64, 64, 3);
        let hand = Hand::default();
        let mut effects = effects_with(EffectKind::Blur, Box::new(AllBackground(16)), &hand);
        assert!(run_until_warm(&mut effects, &mut picture, &hand));
        picture.y.clone()
    };

    // Floating point in the mask path is the risk here; the composite itself is
    // integer. A difference between runs would mean the result depends on how
    // many frames happened to pass before the mask landed.
    assert_eq!(run(), run());
}
