//! Background blur.
//!
//! Three passes of a separable box blur rather than one Gaussian: the result is
//! visually indistinguishable at these radii, and the cost is linear in the
//! radius instead of quadratic, which is the difference between fitting in the
//! per-frame budget and not. Each pass runs horizontally then vertically over
//! one plane.
//!
//! Blurring is done on a copy of the plane, because compositing needs both the
//! original (foreground) and the blurred version (background) of every pixel.

use crate::frame::{I420FrameMut, Plane};

/// How many box passes approximate the Gaussian. Three is the usual answer:
/// two still shows the box's flat shoulder, four costs a third more for no
/// visible gain.
const PASSES: usize = 3;

/// A plane lifted out of a frame, blurred, and ready to composite back in.
pub struct BlurredPlane {
    pub width: usize,
    pub height: usize,
    pixels: Vec<u8>,
}

impl BlurredPlane {
    pub fn at(&self, x: usize, y: usize) -> u8 {
        self.pixels[y * self.width + x]
    }
}

/// Copies `plane` out of `frame` and blurs it with the given radius in pixels.
/// A radius of 0 returns the plane unchanged, which is what makes the
/// degradation ladder's weakest step free rather than a special case.
pub fn blur_plane(frame: &I420FrameMut<'_>, plane: Plane, radius: usize) -> BlurredPlane {
    let width = frame.plane_width(plane);
    let height = frame.plane_height(plane);

    let mut pixels = Vec::with_capacity(width * height);
    for y in 0..height {
        pixels.extend_from_slice(frame.row(plane, y));
    }

    let mut blurred = BlurredPlane { width, height, pixels };

    if radius == 0 || width == 0 || height == 0 {
        return blurred;
    }

    let mut scratch = vec![0u8; width * height];
    for _ in 0..PASSES {
        box_pass_horizontal(&blurred.pixels, &mut scratch, width, height, radius);
        box_pass_vertical(&scratch, &mut blurred.pixels, width, height, radius);
    }

    blurred
}

/// The blur radius for a frame of this height, as a fraction of it.
///
/// Expressed relative to the frame so the effect looks the same at every
/// capture resolution — a fixed pixel radius is a heavy blur at 360p and barely
/// visible at 1080p. `strength` is the 0..1 the UI's slider gives.
pub fn radius_for(height: usize, strength: f32) -> usize {
    /// The strongest blur, as a fraction of frame height. Past this the
    /// background turns into flat colour and the picture stops reading as a
    /// room at all.
    const MAX_FRACTION: f32 = 0.06;

    let fraction = strength.clamp(0.0, 1.0) * MAX_FRACTION;
    ((height as f32) * fraction).round().max(0.0) as usize
}

/// How many columns the vertical pass carries at once.
///
/// The vertical pass is the expensive half, and not because of the arithmetic:
/// walking one column touches a new cache line for every pixel. Carrying a
/// block of columns together means each line that is loaded serves the whole
/// block, and the inner loops become contiguous runs the compiler can
/// vectorise. 32 is one 64-byte line of `u8` either side of any alignment.
const COLUMN_BLOCK: usize = 32;

/// Divides by the window width without dividing.
///
/// `sum / window` once per pixel is six million integer divisions a frame at
/// 540p, and an integer division is an order of magnitude dearer than a
/// multiply. This is the textbook reciprocal: `floor(sum * m / 2^32)` with
/// `m = ceil(2^32 / window)`.
///
/// **It is exact, not an approximation.** With `m = ceil(2^32 / d)` the error
/// `e = m * d - 2^32` is smaller than `d`, and the identity holds for every
/// `sum` up to `2^32 / e`. Here `d` is `2 * radius + 1` and `sum` is at most
/// `255 * d`, so even a radius of a thousand leaves four orders of magnitude of
/// headroom. The blurred planes come out byte-for-byte as they did with the
/// division, which is what the determinism test pins.
#[derive(Clone, Copy)]
struct Reciprocal(u64);

impl Reciprocal {
    fn of(window: u32) -> Self {
        Self(((1u64 << 32) + u64::from(window) - 1) / u64::from(window))
    }

    #[inline(always)]
    fn apply(self, sum: u32) -> u8 {
        ((u64::from(sum) * self.0) >> 32) as u8
    }
}

fn box_pass_horizontal(source: &[u8], out: &mut [u8], width: usize, height: usize, radius: usize) {
    let mean = Reciprocal::of((radius * 2 + 1) as u32);

    for y in 0..height {
        let row = &source[y * width..y * width + width];
        let out_row = &mut out[y * width..y * width + width];

        // A running sum, so each output pixel costs one add and one subtract
        // however wide the window is. Edges clamp to the outermost pixel, which
        // keeps the border from darkening towards an imaginary black surround.
        let mut sum: u32 = 0;
        for x in 0..=radius {
            sum += u32::from(row[x.min(width - 1)]);
        }
        sum += u32::from(row[0]) * radius as u32;

        for x in 0..width {
            out_row[x] = mean.apply(sum);

            let leaving = row[x.saturating_sub(radius)];
            let entering = row[(x + radius + 1).min(width - 1)];
            sum = sum + u32::from(entering) - u32::from(leaving);
        }
    }
}

fn box_pass_vertical(source: &[u8], out: &mut [u8], width: usize, height: usize, radius: usize) {
    let mean = Reciprocal::of((radius * 2 + 1) as u32);
    let mut sums = [0u32; COLUMN_BLOCK];

    for start in (0..width).step_by(COLUMN_BLOCK) {
        let span = COLUMN_BLOCK.min(width - start);
        let columns = &mut sums[..span];

        columns.fill(0);
        for y in 0..=radius {
            let row = &source[y.min(height - 1) * width + start..][..span];
            for (sum, &pixel) in columns.iter_mut().zip(row) {
                *sum += u32::from(pixel);
            }
        }
        let first = &source[start..start + span];
        for (sum, &pixel) in columns.iter_mut().zip(first) {
            *sum += u32::from(pixel) * radius as u32;
        }

        for y in 0..height {
            let out_row = &mut out[y * width + start..][..span];
            for (slot, &sum) in out_row.iter_mut().zip(columns.iter()) {
                *slot = mean.apply(sum);
            }

            let leaving = &source[y.saturating_sub(radius) * width + start..][..span];
            let entering = &source[(y + radius + 1).min(height - 1) * width + start..][..span];
            for ((sum, &out), &into) in columns.iter_mut().zip(leaving).zip(entering) {
                *sum = *sum + u32::from(into) - u32::from(out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reciprocal is the one piece of cleverness in this file, and the
    /// whole case for it is that it is *exact*. So this checks it against the
    /// division it replaces, for every window a radius can produce and every
    /// sum that window can hold — which is the entire input domain, not a
    /// sample of it.
    #[test]
    fn the_reciprocal_divides_exactly() {
        for radius in [0usize, 1, 2, 3, 7, 23, 43, 64, 128, 512, 1024] {
            let window = (radius * 2 + 1) as u32;
            let mean = Reciprocal::of(window);

            for sum in 0..=255 * window {
                assert_eq!(
                    u32::from(mean.apply(sum)),
                    sum / window,
                    "radius {radius}, window {window}, sum {sum}"
                );
            }
        }
    }

    /// The vertical pass carries columns in blocks, so a width that is not a
    /// multiple of the block has a short last one. Compared against a plain
    /// column-at-a-time pass rather than against recorded numbers, so the
    /// comparison stays true if the radius or the blocking ever change.
    #[test]
    fn blocking_the_vertical_pass_changes_nothing() {
        for (width, height) in [(1usize, 1usize), (31, 5), (32, 8), (33, 8), (65, 3), (96, 64)] {
            let source: Vec<u8> = (0..width * height).map(|i| (i * 37 % 251) as u8).collect();

            for radius in [1usize, 2, 5] {
                let mut blocked = vec![0u8; width * height];
                box_pass_vertical(&source, &mut blocked, width, height, radius);

                let window = (radius * 2 + 1) as u32;
                let mut plain = vec![0u8; width * height];
                for x in 0..width {
                    for y in 0..height {
                        let mut sum = 0u32;
                        for tap in 0..=(radius * 2) {
                            let row = (y + tap).saturating_sub(radius).min(height - 1);
                            sum += u32::from(source[row * width + x]);
                        }
                        plain[y * width + x] = (sum / window) as u8;
                    }
                }

                assert_eq!(blocked, plain, "{width}x{height}, radius {radius}");
            }
        }
    }
}
