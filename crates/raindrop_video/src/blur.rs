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

fn box_pass_horizontal(source: &[u8], out: &mut [u8], width: usize, height: usize, radius: usize) {
    let window = (radius * 2 + 1) as u32;

    for y in 0..height {
        let row = &source[y * width..y * width + width];

        // A running sum, so each output pixel costs one add and one subtract
        // however wide the window is. Edges clamp to the outermost pixel, which
        // keeps the border from darkening towards an imaginary black surround.
        let mut sum: u32 = 0;
        for x in 0..=radius {
            sum += u32::from(row[x.min(width - 1)]);
        }
        sum += u32::from(row[0]) * radius as u32;

        for x in 0..width {
            out[y * width + x] = (sum / window) as u8;

            let leaving = row[x.saturating_sub(radius)];
            let entering = row[(x + radius + 1).min(width - 1)];
            sum = sum + u32::from(entering) - u32::from(leaving);
        }
    }
}

fn box_pass_vertical(source: &[u8], out: &mut [u8], width: usize, height: usize, radius: usize) {
    let window = (radius * 2 + 1) as u32;

    for x in 0..width {
        let mut sum: u32 = 0;
        for y in 0..=radius {
            sum += u32::from(source[y.min(height - 1) * width + x]);
        }
        sum += u32::from(source[x]) * radius as u32;

        for y in 0..height {
            out[y * width + x] = (sum / window) as u8;

            let leaving = source[y.saturating_sub(radius) * width + x];
            let entering = source[(y + radius + 1).min(height - 1) * width + x];
            sum = sum + u32::from(entering) - u32::from(leaving);
        }
    }
}
