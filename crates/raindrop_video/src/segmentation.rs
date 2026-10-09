//! Finding the person.
//!
//! Behind a trait, for two reasons. The first is that the pixel work in this
//! crate — the blur, the composite, the mask handling — is most of the code and
//! all of the per-frame cost, and none of it should have to know what produced
//! the mask. The second is that the runtime is the part of this crate most
//! likely to be swapped: a pure-Rust inference engine is what makes the one
//! cargokit build work on all five targets, and a platform-native or
//! accelerated backend may later beat it on some of them. Measuring that is
//! only possible if both can be put behind the same call.
//!
//! A segmenter is asked for a mask at its own natural size; stretching it over
//! the frame is [`crate::mask`]'s job.

use crate::Error;
use crate::mask::Mask;

/// Turns a square of RGB into a foreground mask.
///
/// Implementations run on the pipeline's worker thread, never on the capture
/// thread, so they may take milliseconds. They must not panic: an error is a
/// mask that did not arrive, which the pipeline survives by keeping the
/// previous one.
pub trait Segmenter: Send {
    /// What this segmenter is, for [`crate::Stats::backend`] and for the logs.
    fn name(&self) -> &'static str;

    /// The side of the square of RGB it wants. The pipeline samples exactly
    /// this, so a segmenter never has to resize its own input.
    fn input_size(&self) -> usize;

    /// `rgb` is `input_size()` squared, RGB888, row-major.
    fn segment(&mut self, rgb: &[u8]) -> Result<Mask, Error>;
}

/// A segmenter that marks the middle of the frame as foreground.
///
/// Not a mock: it is a real, deterministic segmenter, which is what lets every
/// pixel path in this crate be tested — the blur, the composite, the scaling,
/// the smoothing, the whole degradation ladder — without an inference runtime
/// or a model file in the way. The tests assert on a shape they chose, so a
/// regression in the pixel work shows up as a wrong picture rather than as a
/// worse mask.
pub struct CentreOvalSegmenter {
    size: usize,
}

impl CentreOvalSegmenter {
    pub fn new(size: usize) -> Self {
        Self { size }
    }
}

impl Default for CentreOvalSegmenter {
    fn default() -> Self {
        Self::new(64)
    }
}

impl Segmenter for CentreOvalSegmenter {
    fn name(&self) -> &'static str {
        "centre-oval"
    }

    fn input_size(&self) -> usize {
        self.size
    }

    fn segment(&mut self, rgb: &[u8]) -> Result<Mask, Error> {
        let size = self.size;
        if rgb.len() < size * size * 3 {
            return Err(Error::Segmentation("the input square was the wrong size"));
        }

        let mut mask = Mask::new(size, size);
        let centre = (size as f32 - 1.0) / 2.0;
        let radius = size as f32 * 0.3;

        for y in 0..size {
            for x in 0..size {
                let dx = (x as f32 - centre) / radius;
                let dy = (y as f32 - centre) / radius;
                mask.alpha[y * size + x] = if dx * dx + dy * dy <= 1.0 { 255 } else { 0 };
            }
        }

        Ok(mask)
    }
}
