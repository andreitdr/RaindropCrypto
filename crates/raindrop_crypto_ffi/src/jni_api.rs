//! The per-frame entry point for Android, as a JNI method.
//!
//! Android is the one target that cannot reach [`crate::c_api`] by address:
//! camera frames arrive in Java, their planes are `java.nio.ByteBuffer`s, and
//! turning one into a pointer needs `GetDirectBufferAddress`, which only JNI
//! can answer. A Java method cannot call a function pointer at all.
//!
//! The alternative was a second native library inside the Flutter plugin — a
//! CMake block, an NDK toolchain of the plugin's own, and a `.so` to keep in
//! step with this one. Exporting the JNI symbol from the library cargokit
//! already cross-compiles costs none of that: the plugin's Java side only needs
//! `System.loadLibrary("raindrop_crypto_ffi")`.
//!
//! The Java class name is a contract this crate owns, not the client's:
//! **`com.raindrop.video.NativeFrameProcessor.processI420`**, deliberately in a
//! different package from whatever plugin declares it, so this crate encodes
//! nothing about the client's internals. See `docs/video-effects.md`.

use jni::errors::LogErrorAndDefault;
use jni::objects::{JByteBuffer, JClass};
use jni::sys::{jint, jlong};
use jni::{Env, EnvUnowned};

/// A plane the JVM did not describe in a way that can be true: not a direct
/// buffer, a negative offset, or too small for the dimensions claimed.
const BAD_PLANE: jint = -4;

/// The processor panicked. Reported rather than hidden behind a 0, which would
/// claim the frame had been processed when it was in fact passed on untouched.
const PANICKED: jint = crate::c_api::PANICKED;

/// Rewrites one I420 frame in place, with the planes a Java
/// `VideoFrame.I420Buffer` hands over. Returns 0 when the frame was processed
/// and a negative number when it was left exactly as it arrived — the same
/// contract as [`crate::c_api::raindrop_video_process_i420`], plus
/// [`BAD_PLANE`] and [`PANICKED`].
///
/// Each plane arrives as its buffer **plus an offset**, because a cropped or
/// scaled I420 buffer is a view whose `position()` is not zero, while
/// `GetDirectBufferAddress` answers for the whole region.
///
/// `with_env` wraps the body in `catch_unwind`, so a panic on the capture
/// thread costs one frame instead of the process.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_raindrop_video_NativeFrameProcessor_processI420<'local>(
    mut unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    context: jlong,
    y: JByteBuffer<'local>,
    y_offset: jint,
    y_stride: jint,
    u: JByteBuffer<'local>,
    u_offset: jint,
    u_stride: jint,
    v: JByteBuffer<'local>,
    v_offset: jint,
    v_stride: jint,
    width: jint,
    height: jint,
) -> jint {
    // Option, not a bare jint: `resolve` falls back to `Default`, and 0 is
    // "processed" in this protocol. `None` is the one value that cannot be
    // mistaken for a frame that was touched.
    let outcome = unowned.with_env(|env| -> jni::errors::Result<Option<jint>> {
        if width <= 0 || height <= 0 {
            return Ok(Some(-1));
        }

        // Chroma planes are half-size rounded up, the same arithmetic
        // raindrop_video uses, so an odd height does not come out a row short.
        let chroma_rows = (i64::from(height) + 1) / 2;

        let Some(y) = plane(env, &y, y_offset, y_stride, i64::from(height)) else {
            return Ok(Some(BAD_PLANE));
        };
        let Some(u) = plane(env, &u, u_offset, u_stride, chroma_rows) else {
            return Ok(Some(BAD_PLANE));
        };
        let Some(v) = plane(env, &v, v_offset, v_stride, chroma_rows) else {
            return Ok(Some(BAD_PLANE));
        };

        // SAFETY: `plane` has established that each pointer is a direct buffer's
        // own memory plus an in-range offset, with `stride * rows` bytes
        // available from there. The Java frame processor holds the only
        // reference to the frame for the duration of this call.
        Ok(Some(unsafe {
            crate::c_api::raindrop_video_process_i420(context, y, y_stride, u, u_stride, v, v_stride, width, height)
        }))
    });

    outcome.resolve::<LogErrorAndDefault>().unwrap_or(PANICKED)
}

/// The writable start of one plane, or `None` when the JVM hands over something
/// that cannot be what it claims.
///
/// Nothing here is trusted. A frame the capture pipeline mis-describes is a
/// frame left alone; the alternative is writing past a buffer.
fn plane(env: &Env<'_>, buffer: &JByteBuffer<'_>, offset: jint, stride: jint, rows: i64) -> Option<*mut u8> {
    if offset < 0 || stride <= 0 {
        return None;
    }

    let address = env.get_direct_buffer_address(buffer).ok()?;
    let capacity = env.get_direct_buffer_capacity(buffer).ok()?;

    if address.is_null() {
        return None;
    }

    let needed = i64::from(offset).checked_add(i64::from(stride).checked_mul(rows)?)?;
    if needed > capacity as i64 {
        return None;
    }

    // SAFETY: `offset` is non-negative and `offset + stride * rows` fits inside
    // the buffer's capacity, so the offset pointer is within the allocation.
    Some(unsafe { address.add(offset as usize) })
}
