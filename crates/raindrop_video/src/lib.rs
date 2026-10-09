//! Raindrop's camera-effects core: background blur and background replacement,
//! applied to camera frames in place.
//!
//! **Why this is Rust, in this workspace.** The effects have to run on all five
//! of the client's targets, and the Flutter media library exposes no way to
//! touch a camera frame from Dart at all — so the work has to happen in native
//! code reached from the capture pipeline. Writing it once here, and letting
//! the same cargokit build that already ships the encryption core carry it,
//! means one segmentation implementation and one set of tests instead of five.
//! The per-platform native code is then only a shim that hands over pointers.
//!
//! **What crosses the boundary.** Frames never reach Dart. The client holds a
//! handle to an [`Effects`] and an address for a C function; the platform's
//! capture pipeline calls that function per frame with the handle as context,
//! and the planes are rewritten where they lie. There is no second track, no
//! copy of the picture, and nothing for the frame cryptor to notice — which is
//! what keeps the effects entirely separate from the end-to-end encryption.
//!
//! ```no_run
//! use raindrop_video::{Config, EffectKind, Effects};
//!
//! let mut effects = Effects::new(Config { kind: EffectKind::Blur, ..Config::default() })?;
//! // per frame, on the capture thread:
//! // effects.process(&mut frame)?;
//! # Ok::<(), raindrop_video::Error>(())
//! ```

pub mod blur;
pub mod convert;
pub mod frame;
pub mod mask;
pub mod pipeline;
pub mod replace;
pub mod segmentation;

use std::time::Duration;

use crate::blur::{blur_plane, radius_for};
use crate::frame::{I420FrameMut, Plane};
use crate::mask::Mask;
use crate::pipeline::{Budget, Degradation, MaskClock, MaskWorker, SystemTime, TimeSource};
use crate::replace::{Background, BackgroundPlanes};
use crate::segmentation::{CentreOvalSegmenter, Segmenter};

/// What went wrong. Coarse on purpose, like the encryption core's: the variant
/// says what kind of failure it was, and the string is for logs, never parsed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The frame's pointers, strides or dimensions do not describe a picture.
    #[error("that is not a frame this can work on: {0}")]
    BadFrame(&'static str),

    /// A replacement background could not be used.
    #[error("that background cannot be used: {0}")]
    BadBackground(&'static str),

    /// Segmentation failed. Never fatal: the previous mask stays current.
    #[error("the person could not be found in the picture: {0}")]
    Segmentation(&'static str),

    /// Asked to replace the background with nothing.
    #[error("no background picture has been chosen")]
    NoBackground,
}

/// Which effect to apply.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum EffectKind {
    /// Frames pass through untouched, and no segmentation runs at all.
    #[default]
    None,
    Blur,
    /// Needs a background; without one, [`Error::NoBackground`].
    Replace,
}

/// How the effects behave. Everything here is the user's choice except
/// [`Self::mask_hz`], which is a performance dial the UI does not show.
#[derive(Clone, Debug)]
pub struct Config {
    pub kind: EffectKind,

    /// 0 to 1, the UI's slider. Mapped to a radius relative to the frame's
    /// height, so the effect looks the same at every capture resolution.
    pub blur_strength: f32,

    /// How often segmentation runs, independent of the frame rate. Well below
    /// it on purpose: a person does not move far in 60ms, and this is where
    /// almost all the cost is.
    pub mask_hz: f32,

    /// How long one frame's compositing may take before the degradation ladder
    /// starts counting. Sustained overruns of twice this step it down.
    pub frame_budget: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            kind: EffectKind::None,
            blur_strength: 0.7,
            mask_hz: 15.0,
            frame_budget: Duration::from_millis(5),
        }
    }
}

/// What the effects are costing, for the UI and for profiling.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub frames: u64,
    pub masks: u64,
    /// How many times the degradation ladder stepped down.
    pub degradations: u32,
    /// True once anything has been given up; the UI says so once.
    pub degraded: bool,
    /// What is currently being given up.
    pub level: Degradation,
}

/// One camera's effects. Created when a camera is opened, dropped when it
/// closes; not `Sync`, because it is driven from the capture thread alone.
pub struct Effects {
    config: Config,
    worker: Option<MaskWorker>,
    clock: MaskClock,
    budget: Budget,
    time: Box<dyn TimeSource>,
    background: Option<Background>,
    cached: Option<BackgroundPlanes>,
    rgb: Vec<u8>,
    scaled: Option<Mask>,
    frames: u64,
    degradations: u32,
}

impl Effects {
    /// Starts the effects, spawning the segmentation worker when the effect
    /// needs one.
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::with_parts(
            config,
            Box::new(CentreOvalSegmenter::default()),
            Box::new(SystemTime::default()),
        )
    }

    /// The seam the tests and a future accelerated backend come in through.
    pub fn with_parts(config: Config, segmenter: Box<dyn Segmenter>, time: Box<dyn TimeSource>) -> Result<Self, Error> {
        let mut effects = Self {
            clock: MaskClock::new(config.mask_hz),
            budget: Budget::new(config.frame_budget),
            worker: None,
            time,
            background: None,
            cached: None,
            rgb: Vec::new(),
            scaled: None,
            frames: 0,
            degradations: 0,
            config,
        };

        if effects.config.kind != EffectKind::None {
            effects.worker = Some(MaskWorker::spawn(segmenter));
        }

        Ok(effects)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Changes what the effects do, keeping the worker and the current mask.
    ///
    /// Switching effect is free — the mask is the expensive part and it is the
    /// same mask whether the background is blurred or replaced, which is why
    /// the pre-join sheet can preview both without restarting the camera.
    /// Switching *away* from [`EffectKind::None`] starts the worker, and back to
    /// it stops the worker rather than leaving a thread segmenting frames
    /// nobody will use.
    pub fn set_config(&mut self, config: Config) -> Result<(), Error> {
        self.clock.set_rate(config.mask_hz);

        match (self.config.kind, config.kind) {
            (EffectKind::None, EffectKind::None) => {}
            (EffectKind::None, _) => {
                self.worker = Some(MaskWorker::spawn(Box::new(CentreOvalSegmenter::default())));
                self.clock = MaskClock::new(config.mask_hz);
            }
            (_, EffectKind::None) => self.worker = None,
            _ => {}
        }

        self.config = config;
        Ok(())
    }

    /// Sets the picture a replaced background shows. Converted to planes lazily,
    /// at the first frame's size.
    pub fn set_background(&mut self, background: Background) -> Result<(), Error> {
        if background.pixels.len() < background.width * background.height * 3 {
            return Err(Error::BadBackground("the picture is smaller than its dimensions say"));
        }

        self.background = Some(background);
        self.cached = None;
        Ok(())
    }

    pub fn clear_background(&mut self) {
        self.background = None;
        self.cached = None;
    }

    pub fn stats(&self) -> Stats {
        Stats {
            frames: self.frames,
            masks: self.clock.masks,
            degradations: self.degradations,
            degraded: self.budget.level() != Degradation::None,
            level: self.budget.level(),
        }
    }

    /// What the segmenter in use is called, for the UI and the logs.
    pub fn backend(&self) -> &'static str {
        self.worker.as_ref().map_or("none", MaskWorker::name)
    }

    /// Rewrites one frame in place.
    ///
    /// Called on the capture thread, per frame. It never blocks on the
    /// segmentation worker and never allocates per pixel; what it does allocate
    /// (the blurred plane, the background's planes) is reused across frames at
    /// the same size.
    pub fn process(&mut self, frame: &mut I420FrameMut<'_>) -> Result<(), Error> {
        self.frames += 1;

        let level = self.budget.level();
        if self.config.kind == EffectKind::None || level == Degradation::Off {
            return Ok(());
        }

        // Replacing the background with nothing is a configuration mistake, and
        // saying so is better than quietly blurring instead.
        if self.config.kind == EffectKind::Replace && self.background.is_none() {
            return Err(Error::NoBackground);
        }

        let started = self.time.now();

        self.collect_mask(frame, started);
        let applied = self.composite(frame, level);

        let elapsed = self.time.now().saturating_sub(started);
        if self.budget.frame_took(elapsed) {
            self.degradations += 1;
            // A step down may have changed the mask rate; apply it at once
            // rather than on the next config change.
            self.clock.set_rate(self.effective_mask_hz(self.budget.level()));
        }

        applied
    }

    /// Takes whatever the worker has finished, and offers it the next square if
    /// one is due.
    fn collect_mask(&mut self, frame: &I420FrameMut<'_>, now: Duration) {
        let Some(worker) = self.worker.as_ref() else { return };

        if let Some(mask) = worker.take_newest() {
            self.clock.arrived(mask);
            // The scaled copy is cached per mask, since a 256-to-frame stretch
            // is not worth repeating for frames that share a mask.
            self.scaled = None;
        }

        if !self.clock.due(now) {
            return;
        }

        let size = worker.input_size();
        convert::frame_to_rgb_square(frame, size, &mut self.rgb);

        // A declined offer means the worker is still busy, which is the normal
        // state under load and not something to report.
        if worker.offer(std::mem::take(&mut self.rgb)) {
            self.clock.asked(now);
        }
    }

    fn effective_mask_hz(&self, level: Degradation) -> f32 {
        match level {
            Degradation::None => self.config.mask_hz,
            Degradation::HalfMaskRate | Degradation::CoarseBlur => self.config.mask_hz / 2.0,
            Degradation::Off => 0.0,
        }
    }

    /// Blends the background treatment into the frame, through the mask.
    fn composite(&mut self, frame: &mut I420FrameMut<'_>, level: Degradation) -> Result<(), Error> {
        // Nothing found yet: pass the frame through rather than blurring a
        // person who has not been located.
        if !self.clock.warm {
            return Ok(());
        }

        let width = frame.width();
        let height = frame.height();

        if self
            .scaled
            .as_ref()
            .is_none_or(|m| m.width != width || m.height != height)
        {
            self.scaled = Some(self.clock.current.scaled_to(width, height));
        }

        match self.config.kind {
            EffectKind::None => Ok(()),
            EffectKind::Blur => {
                let divisor = if level == Degradation::CoarseBlur { 4 } else { 1 };
                let radius = radius_for(height, self.config.blur_strength) / divisor;
                let luma = blur_plane(frame, Plane::Y, radius);
                let u = blur_plane(frame, Plane::U, radius / 2);
                let v = blur_plane(frame, Plane::V, radius / 2);

                self.blend(frame, |plane, x, y| match plane {
                    Plane::Y => luma.at(x, y),
                    Plane::U => u.at(x, y),
                    Plane::V => v.at(x, y),
                });
                Ok(())
            }
            EffectKind::Replace => {
                let background = self.background.as_ref().ok_or(Error::NoBackground)?;

                if self
                    .cached
                    .as_ref()
                    .is_none_or(|c| c.width != width || c.height != height)
                {
                    self.cached = Some(BackgroundPlanes::build(background, width, height));
                }
                let planes = self.cached.as_ref().expect("just built");

                self.blend(frame, |plane, x, y| match plane {
                    Plane::Y => planes.luma(x, y),
                    Plane::U => planes.chroma(x, y).0,
                    Plane::V => planes.chroma(x, y).1,
                });
                Ok(())
            }
        }
    }

    /// Mixes each plane towards what `background` says, by how much the mask
    /// says the pixel is *not* foreground.
    ///
    /// Chroma is sampled from the mask at twice the step, which is the whole of
    /// what makes this work on subsampled planes: one mask covers a 2×2 block
    /// of luma and one chroma sample, so the blend stays aligned.
    fn blend<F>(&self, frame: &mut I420FrameMut<'_>, background: F)
    where
        F: Fn(Plane, usize, usize) -> u8,
    {
        let mask = self.scaled.as_ref().expect("scaled before blending");

        for y in 0..frame.height() {
            let row = frame.row_mut(Plane::Y, y);
            for (x, pixel) in row.iter_mut().enumerate() {
                *pixel = mix(*pixel, background(Plane::Y, x, y), mask.at(x, y));
            }
        }

        let chroma_width = frame.chroma_width();
        let chroma_height = frame.chroma_height();
        let last_x = frame.width() - 1;
        let last_y = frame.height() - 1;

        for plane in [Plane::U, Plane::V] {
            for y in 0..chroma_height {
                let mask_y = (y * 2).min(last_y);
                let row = frame.row_mut(plane, y);

                for x in 0..chroma_width.min(row.len()) {
                    let mask_x = (x * 2).min(last_x);
                    row[x] = mix(row[x], background(plane, x, y), mask.at(mask_x, mask_y));
                }
            }
        }
    }
}

/// `foreground` where the mask is 255, `background` where it is 0.
fn mix(foreground: u8, background: u8, alpha: u8) -> u8 {
    let a = u32::from(alpha);
    let blended = u32::from(foreground) * a + u32::from(background) * (255 - a);
    // +127 rounds rather than truncates, which matters: truncating drifts the
    // whole picture a shade darker every time an effect is applied.
    ((blended + 127) / 255) as u8
}
