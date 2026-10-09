//! Background replacement.
//!
//! A replacement image is converted to I420 **once**, at the frame's size, and
//! cached — a per-frame RGB-to-YUV pass over a whole picture would cost more
//! than the blur does. The cache is keyed by the size it was built for, so a
//! resolution change rebuilds it and nothing else notices.
//!
//! The image is scaled to cover the frame and centre-cropped, like a CSS
//! `background-size: cover`, so a replacement of any aspect ratio fills the
//! picture without being stretched.

use crate::convert::rgb_to_yuv;

/// A decoded replacement image, in the caller's colour space.
#[derive(Clone, Debug)]
pub struct Background {
    pub width: usize,
    pub height: usize,
    /// RGB888, `width * height * 3` bytes.
    pub pixels: Vec<u8>,
}

/// A replacement image converted to planes at one particular frame size.
pub struct BackgroundPlanes {
    pub width: usize,
    pub height: usize,
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
    chroma_width: usize,
}

impl BackgroundPlanes {
    pub fn luma(&self, x: usize, y: usize) -> u8 {
        self.y[y * self.width + x]
    }

    pub fn chroma(&self, x: usize, y: usize) -> (u8, u8) {
        let index = y * self.chroma_width + x;
        (self.u[index], self.v[index])
    }

    /// Builds the planes for a frame of this size, cropping to cover.
    pub fn build(background: &Background, width: usize, height: usize) -> Self {
        let chroma_width = width.div_ceil(2);
        let chroma_height = height.div_ceil(2);

        let mut planes = Self {
            width,
            height,
            y: vec![16; width * height],
            u: vec![128; chroma_width * chroma_height],
            v: vec![128; chroma_width * chroma_height],
            chroma_width,
        };

        if background.width == 0 || background.height == 0 || width == 0 || height == 0 {
            return planes;
        }

        // Cover: scale by whichever axis needs the most, then take the middle.
        let scale = (width as f32 / background.width as f32).max(height as f32 / background.height as f32);
        let scaled_width = (background.width as f32 * scale).max(1.0);
        let scaled_height = (background.height as f32 * scale).max(1.0);
        let left = (scaled_width - width as f32) / 2.0;
        let top = (scaled_height - height as f32) / 2.0;

        let sample = |x: usize, y: usize| -> (u8, u8, u8) {
            let source_x = (((x as f32 + left) / scale) as usize).min(background.width - 1);
            let source_y = (((y as f32 + top) / scale) as usize).min(background.height - 1);
            let index = (source_y * background.width + source_x) * 3;
            rgb_to_yuv(
                background.pixels[index],
                background.pixels[index + 1],
                background.pixels[index + 2],
            )
        };

        for y in 0..height {
            for x in 0..width {
                planes.y[y * width + x] = sample(x, y).0;
            }
        }

        // Chroma is sampled from the pixel each 2×2 block starts at, matching
        // how the composite reads it back.
        for y in 0..chroma_height {
            for x in 0..chroma_width {
                let (_, u, v) = sample((x * 2).min(width - 1), (y * 2).min(height - 1));
                planes.u[y * chroma_width + x] = u;
                planes.v[y * chroma_width + x] = v;
            }
        }

        planes
    }
}
