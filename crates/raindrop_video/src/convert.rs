//! Colour conversion, only where it is unavoidable.
//!
//! Effects work directly on I420 — the blur and the composite never leave it,
//! which is most of why they fit in the budget. The one thing that cannot is
//! the segmentation model, which wants a small square of RGB. So exactly one
//! conversion happens per mask update (not per frame), over a 256×256 window
//! rather than the whole picture.
//!
//! BT.601 limited range is used throughout, which is what a webcam produces.

use crate::frame::{I420FrameMut, Plane};

/// Fills `out` with `size`×`size` RGB888 sampled from the frame.
///
/// Nearest-neighbour, deliberately: this feeds a 256×256 segmentation model
/// whose own first layers downsample anyway, so the cost of anything better is
/// spent for no gain in the mask.
pub fn frame_to_rgb_square(frame: &I420FrameMut<'_>, size: usize, out: &mut Vec<u8>) {
    out.clear();
    out.reserve(size * size * 3);

    let width = frame.width();
    let height = frame.height();

    for row in 0..size {
        let y = (row * height / size).min(height - 1);
        let luma = frame.row(Plane::Y, y);
        let chroma_y = (y / 2).min(frame.chroma_height() - 1);
        let u_row = frame.row(Plane::U, chroma_y);
        let v_row = frame.row(Plane::V, chroma_y);

        for column in 0..size {
            let x = (column * width / size).min(width - 1);
            let chroma_x = (x / 2).min(frame.chroma_width() - 1);

            let (r, g, b) = yuv_to_rgb(luma[x], u_row[chroma_x], v_row[chroma_x]);
            out.push(r);
            out.push(g);
            out.push(b);
        }
    }
}

/// One pixel, BT.601 limited range, in integer arithmetic.
pub fn yuv_to_rgb(y: u8, u: u8, v: u8) -> (u8, u8, u8) {
    let c = i32::from(y) - 16;
    let d = i32::from(u) - 128;
    let e = i32::from(v) - 128;

    let r = (298 * c + 409 * e + 128) >> 8;
    let g = (298 * c - 100 * d - 208 * e + 128) >> 8;
    let b = (298 * c + 516 * d + 128) >> 8;

    (clamp_byte(r), clamp_byte(g), clamp_byte(b))
}

/// The inverse, for turning a replacement background image into planes once.
pub fn rgb_to_yuv(r: u8, g: u8, b: u8) -> (u8, u8, u8) {
    let r = i32::from(r);
    let g = i32::from(g);
    let b = i32::from(b);

    let y = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
    let u = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
    let v = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;

    (clamp_byte(y), clamp_byte(u), clamp_byte(v))
}

fn clamp_byte(value: i32) -> u8 {
    value.clamp(0, 255) as u8
}
