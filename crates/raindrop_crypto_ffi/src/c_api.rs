//! The per-frame entry point, as a plain C function.
//!
//! This is the hot path, and it deliberately avoids flutter_rust_bridge
//! entirely: it is called from the platform's capture pipeline — Objective-C on
//! Apple, JNI on Android — on the capture thread, dozens of times a second,
//! with the frame's own planes. Going through the bridge would mean marshalling
//! a megabyte of pixels into Dart and back per frame.
//!
//! Native code reaches it by **address**, which Dart asks for with
//! `video_effects_process_address` and passes through as an integer. So the
//! platform code holds no Raindrop symbol, links against nothing of ours, and
//! would work just as well against any other processor.
//!
//! # Safety
//!
//! The caller guarantees the three plane pointers are writable for
//! `stride * height` (and `stride * ((height + 1) / 2)` for chroma) bytes, that
//! the strides are at least their plane's width, and that nothing else touches
//! those planes for the duration of the call. Everything checkable is checked
//! and reported; nothing is trusted.

use raindrop_video::frame::I420FrameMut;

/// The processor panicked. Reported rather than hidden behind a 0, which would claim the frame had
/// been processed when it was in fact passed on untouched. Shared with the JNI surface, which
/// reports the same code.
pub(crate) const PANICKED: i32 = -5;

/// The signature the platform's capture pipeline calls.
///
/// Named so the address handed to Dart goes through a typed pointer, and so the
/// native side has one place to copy the shape from.
pub type ProcessI420 = unsafe extern "C" fn(
    context: i64,
    y: *mut u8,
    y_stride: i32,
    u: *mut u8,
    u_stride: i32,
    v: *mut u8,
    v_stride: i32,
    width: i32,
    height: i32,
) -> i32;

/// Rewrites one I420 frame in place. Returns 0 when the frame was processed,
/// and a negative number when it was left exactly as it arrived.
///
/// A non-zero return is **not** an error the caller has to handle: passing the
/// frame on untouched is always the correct fallback, and is what happens when
/// the effects are busy reconfiguring or the handle has been destroyed.
///
/// # Safety
///
/// `y`, `u` and `v` must be writable for `y_stride * height` and
/// `stride * ((height + 1) / 2)` bytes respectively, each stride must be at
/// least its plane's width, and nothing else may touch those planes for the
/// duration of the call. `context` is a handle from `video_effects_create`; a
/// stale one is reported, not dereferenced. Everything checkable is checked —
/// null planes, non-positive dimensions, a stride narrower than its plane.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn raindrop_video_process_i420(
    context: i64,
    y: *mut u8,
    y_stride: i32,
    u: *mut u8,
    u_stride: i32,
    v: *mut u8,
    v_stride: i32,
    width: i32,
    height: i32,
) -> i32 {
    if width <= 0 || height <= 0 || y_stride <= 0 || u_stride <= 0 || v_stride <= 0 {
        return -1;
    }

    // SAFETY: the caller's contract, documented on this module. Everything that
    // can be checked without trusting them — null planes, zero dimensions, a
    // stride narrower than its plane — `I420FrameMut::new` checks itself.
    let frame = unsafe {
        I420FrameMut::new(
            y,
            y_stride as usize,
            u,
            u_stride as usize,
            v,
            v_stride as usize,
            width as usize,
            height as usize,
        )
    };

    let Ok(mut frame) = frame else {
        return -2;
    };

    guarded(|| crate::api::video::process(context as u64, &mut frame))
}

/// Turns one frame's processing into the return code. A panic must not unwind out of an
/// `extern "C"` function, which aborts the app, so it is caught here and reported as [`PANICKED`]:
/// the frame is passed on untouched, costing one frame rather than the process.
pub(crate) fn guarded(process: impl FnOnce() -> bool) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(process)) {
        Ok(true) => 0,
        Ok(false) => -3,
        Err(_) => PANICKED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panicking_processor_is_reported_not_unwound() {
        assert_eq!(guarded(|| panic!("injected test panic")), PANICKED);
    }

    #[test]
    fn processed_and_untouched_frames_keep_their_codes() {
        assert_eq!(guarded(|| true), 0);
        assert_eq!(guarded(|| false), -3);
    }
}
