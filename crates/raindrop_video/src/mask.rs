//! The person mask: where the foreground is, and how it is smoothed.
//!
//! The segmentation model works at a fixed small size (see [`crate::segmentation`]),
//! so a mask arrives much coarser than the frame and has to be stretched over
//! it. Two things stop that looking wrong:
//!
//! - **Bilinear upscaling**, so the edge is a gradient rather than a staircase.
//! - **Temporal smoothing**, so a mask that is only recomputed every few frames
//!   does not make the edge crawl. It costs a little lag, which is why the
//!   weight lives in one named constant rather than being spread around.

/// A per-pixel foreground confidence, 0 background and 255 foreground.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mask {
    pub width: usize,
    pub height: usize,
    pub alpha: Vec<u8>,
}

/// How much of the previous mask survives into the next one.
///
/// Mask updates are slower than the frame rate on purpose, and without this the
/// boundary visibly jumps each time a new one lands. Higher is steadier and
/// lags further behind a moving subject; 0.6 is the point where a person turning
/// their head stops shimmering without the blur edge trailing them.
pub const SMOOTHING: f32 = 0.6;

impl Mask {
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            alpha: vec![0; width * height],
        }
    }

    /// Everything foreground — what a frame is composited against before any
    /// mask has arrived, so the first frames pass through untouched rather than
    /// being blurred to nothing.
    pub fn opaque(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            alpha: vec![255; width * height],
        }
    }

    pub fn at(&self, x: usize, y: usize) -> u8 {
        self.alpha[y * self.width + x]
    }

    /// Blends `next` into this mask, in place. Sizes must match; a mismatch
    /// replaces rather than blends, since a resolution change has no sensible
    /// previous mask to carry over.
    pub fn smooth_towards(&mut self, next: &Mask, weight: f32) {
        if self.width != next.width || self.height != next.height {
            *self = next.clone();
            return;
        }

        let keep = weight.clamp(0.0, 1.0);
        let take = 1.0 - keep;

        for (current, fresh) in self.alpha.iter_mut().zip(next.alpha.iter()) {
            let blended = (f32::from(*current) * keep + f32::from(*fresh) * take).round() as u8;

            *current = if blended == *current && *current != *fresh {
                // Rounding stalls one short: blending 1 towards 0 at 0.6 gives
                // 0.6, which rounds back to 1 forever. Left alone, a mask never
                // quite reaches full background, so the blur stays a shade off
                // everywhere it should have faded out completely. Step the last
                // unit by hand so a mask really does converge.
                if *fresh > *current { *current + 1 } else { *current - 1 }
            } else {
                blended
            };
        }
    }

    /// Stretches this mask to `width` by `height`, bilinearly.
    ///
    /// Sampling at pixel centres (the +0.5) rather than at corners is what
    /// keeps the result centred; sampling at corners shifts the whole mask by
    /// half a source pixel, which at this scale factor is several pixels of
    /// frame and reads as the blur being offset from the person.
    pub fn scaled_to(&self, width: usize, height: usize) -> Mask {
        if width == self.width && height == self.height {
            return self.clone();
        }

        let mut out = Mask::new(width, height);
        if width == 0 || height == 0 || self.width == 0 || self.height == 0 {
            return out;
        }

        let x_ratio = self.width as f32 / width as f32;
        let y_ratio = self.height as f32 / height as f32;
        let last_x = self.width - 1;
        let last_y = self.height - 1;

        for y in 0..height {
            let source_y = ((y as f32 + 0.5) * y_ratio - 0.5).max(0.0);
            let y0 = (source_y as usize).min(last_y);
            let y1 = (y0 + 1).min(last_y);
            let fy = source_y - y0 as f32;

            for x in 0..width {
                let source_x = ((x as f32 + 0.5) * x_ratio - 0.5).max(0.0);
                let x0 = (source_x as usize).min(last_x);
                let x1 = (x0 + 1).min(last_x);
                let fx = source_x - x0 as f32;

                let top = lerp(self.at(x0, y0), self.at(x1, y0), fx);
                let bottom = lerp(self.at(x0, y1), self.at(x1, y1), fx);

                out.alpha[y * width + x] = lerp_f(top, bottom, fy).round().clamp(0.0, 255.0) as u8;
            }
        }

        out
    }
}

fn lerp(a: u8, b: u8, t: f32) -> f32 {
    lerp_f(f32::from(a), f32::from(b), t)
}

fn lerp_f(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}
