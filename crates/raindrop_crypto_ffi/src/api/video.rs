//! The camera effects, as Dart sees them.
//!
//! **Control only.** Frames never cross this bridge: Dart creates an effects
//! handle, asks for the address of the C function that processes a frame
//! ([`video_effects_process_address`]), and hands both to the platform's
//! capture pipeline, which calls that function per frame with the handle as its
//! context. See [`crate::c_api`] and
//! `../../../raindrop_video/src/lib.rs`.
//!
//! The handle is a plain integer rather than a flutter_rust_bridge opaque
//! object precisely because it has to travel through a Dart `int` into native
//! code that knows nothing about Rust.

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::{Mutex, MutexGuard, OnceLock, TryLockError};

use raindrop_video::replace::Background;
use raindrop_video::{Config, EffectKind, Effects};

/// Flat, like every other bridge type here, so the generated Dart needs no
/// `freezed` and there is no `build_runner` step.
pub struct VideoFailure {
    pub kind: VideoFailureKind,
    pub message: String,
}

pub enum VideoFailureKind {
    /// No segmentation model in this build, so there is nothing to run.
    Unsupported,
    /// The background picture could not be read or decoded.
    BadImage,
    /// No effects exist under that handle — already destroyed.
    BadHandle,
    Other,
}

/// What the effects should do. `kind` is [`VideoEffectKind`]'s index, because
/// the bridge carries flat scalars.
pub struct VideoEffectsConfig {
    pub kind: i32,
    pub blur_strength: f32,
    pub mask_hz: f32,
}

/// Whether effects can run in this build, and what with.
pub struct VideoEffectsCapabilities {
    /// False when no segmentation model is bundled. The UI reads this rather
    /// than guessing from the platform: a build without the model would blur
    /// the wrong shape, which is worse than not offering the effect.
    pub available: bool,
    pub backend: String,
}

pub struct VideoEffectsStats {
    pub frames: u64,
    pub masks: u64,
    pub degraded: bool,
    pub degradations: u32,
}

fn registry() -> &'static Mutex<HashMap<u64, Effects>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, Effects>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Locks the registry, taking it over if an earlier holder panicked.
///
/// A panic while the lock is held would otherwise poison it for good: every later call would fail
/// and the effects would silently stop. The map is still usable after such a panic, so the lock is
/// recovered and the poison flag cleared.
fn lock_registry() -> MutexGuard<'static, HashMap<u64, Effects>> {
    registry().lock().unwrap_or_else(|poisoned| {
        registry().clear_poison();
        poisoned.into_inner()
    })
}

fn next_handle() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn config_of(config: &VideoEffectsConfig) -> Config {
    Config {
        kind: match config.kind {
            1 => EffectKind::Blur,
            2 => EffectKind::Replace,
            _ => EffectKind::None,
        },
        blur_strength: config.blur_strength,
        mask_hz: config.mask_hz,
        ..Config::default()
    }
}

#[flutter_rust_bridge::frb(sync)]
pub fn video_effects_capabilities() -> VideoEffectsCapabilities {
    let backend = raindrop_video::onnx::best_name();
    VideoEffectsCapabilities {
        available: raindrop_video::onnx::model_bundled(),
        backend: backend.to_string(),
    }
}

/// The address of the per-frame C function. Handed to the platform's capture
/// pipeline, which casts and calls it; the frame bytes never come here.
#[flutter_rust_bridge::frb(sync)]
pub fn video_effects_process_address() -> usize {
    // Through a typed function pointer, not a direct `as usize` on the item:
    // casting a function *item* straight to an integer is a different cast and
    // the compiler rightly objects to it.
    let processor: crate::c_api::ProcessI420 = crate::c_api::raindrop_video_process_i420;
    processor as usize
}

pub fn video_effects_create(config: VideoEffectsConfig) -> Result<u64, VideoFailure> {
    if !raindrop_video::onnx::model_bundled() {
        return Err(VideoFailure {
            kind: VideoFailureKind::Unsupported,
            message: "this build has no segmentation model".into(),
        });
    }

    let effects = Effects::new(config_of(&config)).map_err(other)?;
    let handle = next_handle();
    lock_registry().insert(handle, effects);
    Ok(handle)
}

pub fn video_effects_update(handle: u64, config: VideoEffectsConfig) -> Result<(), VideoFailure> {
    let mut registry = lock_registry();
    let effects = registry.get_mut(&handle).ok_or_else(bad_handle)?;
    effects.set_config(config_of(&config)).map_err(other)
}

/// Reads a picture off disk and uses it as the replaced background.
///
/// Decoding happens here rather than in Dart so the pixels never cross the
/// bridge: a 4K photograph would be 24 MB of Dart list otherwise.
pub fn video_effects_set_background_file(handle: u64, path: String) -> Result<(), VideoFailure> {
    let background = Background::from_file(&path).map_err(|_| VideoFailure {
        kind: VideoFailureKind::BadImage,
        message: format!("{path} could not be read as a picture"),
    })?;

    let mut registry = lock_registry();
    let effects = registry.get_mut(&handle).ok_or_else(bad_handle)?;
    effects.set_background(background).map_err(other)
}

pub fn video_effects_stats(handle: u64) -> Result<VideoEffectsStats, VideoFailure> {
    let registry = lock_registry();
    let effects = registry.get(&handle).ok_or_else(bad_handle)?;
    let stats = effects.stats();

    Ok(VideoEffectsStats {
        frames: stats.frames,
        masks: stats.masks,
        degraded: stats.degraded,
        degradations: stats.degradations,
    })
}

/// Releases the effects, and with them the segmentation worker's thread.
///
/// The capture pipeline must have stopped calling the processor first; the
/// handle going missing makes a late call a no-op rather than a crash, but a
/// frame processed after this is a frame that was not.
pub fn video_effects_destroy(handle: u64) {
    lock_registry().remove(&handle);
}

/// Runs one frame through the effects under `handle`.
///
/// Called from [`crate::c_api`] on the capture thread, never from Dart.
pub(crate) fn process(handle: u64, frame: &mut raindrop_video::frame::I420FrameMut<'_>) -> bool {
    // try_lock, never lock: the capture thread must not block behind a
    // configuration change, and a frame left alone for one tick is invisible
    // where a stalled camera is not.
    let mut registry = match registry().try_lock() {
        Ok(registry) => registry,
        Err(TryLockError::Poisoned(poisoned)) => {
            registry().clear_poison();
            poisoned.into_inner()
        }
        Err(TryLockError::WouldBlock) => return false,
    };

    process_in(&mut registry, handle, |effects| effects.process(frame).is_ok())
}

/// Runs `run` on the effects under `handle`, catching a panic inside it.
///
/// The catch happens here, while the registry is still locked and not unwinding, so a panic cannot
/// poison the lock. The effects that panicked are dropped: their state is not trusted after an
/// unwind, and dropping them stops their segmentation worker. The frame is left as it arrived.
fn process_in(registry: &mut HashMap<u64, Effects>, handle: u64, run: impl FnOnce(&mut Effects) -> bool) -> bool {
    let Some(effects) = registry.get_mut(&handle) else {
        return false;
    };

    match std::panic::catch_unwind(AssertUnwindSafe(|| run(effects))) {
        Ok(processed) => processed,
        Err(_) => {
            registry.remove(&handle);
            false
        }
    }
}

fn bad_handle() -> VideoFailure {
    VideoFailure {
        kind: VideoFailureKind::BadHandle,
        message: "there are no camera effects under that handle".into(),
    }
}

fn other(error: raindrop_video::Error) -> VideoFailure {
    VideoFailure {
        kind: VideoFailureKind::Other,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raindrop_video::frame::I420FrameMut;

    fn effects() -> Effects {
        Effects::new(Config::default()).expect("default effects")
    }

    #[test]
    fn a_panicking_effect_is_removed_and_the_frame_left_alone() {
        let mut registry = HashMap::new();
        registry.insert(7, effects());

        assert!(!process_in(&mut registry, 7, |_| panic!("injected test panic")));
        assert!(!registry.contains_key(&7));
    }

    #[test]
    fn a_healthy_effect_keeps_its_result_and_its_entry() {
        let mut registry = HashMap::new();
        registry.insert(7, effects());

        assert!(process_in(&mut registry, 7, |_| true));
        assert!(!process_in(&mut registry, 7, |_| false));
        assert!(registry.contains_key(&7));
        assert!(!process_in(&mut registry, 8, |_| true));
    }

    #[test]
    fn a_poisoned_registry_still_processes_destroys_and_stores() {
        // Poison the registry the way a panic while the lock is held would.
        let _ = std::panic::catch_unwind(|| {
            let _held = registry().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            panic!("injected test panic");
        });
        assert!(registry().is_poisoned());

        let handle = next_handle();
        lock_registry().insert(handle, effects());
        assert!(!registry().is_poisoned());

        let (mut y, mut u, mut v) = (vec![0u8; 16 * 16], vec![0u8; 8 * 8], vec![0u8; 8 * 8]);
        // SAFETY: each plane is a live buffer of at least stride * rows bytes, and nothing else touches them.
        let Ok(mut frame) = (unsafe {
            I420FrameMut::new(y.as_mut_ptr(), 16, u.as_mut_ptr(), 8, v.as_mut_ptr(), 8, 16, 16)
        }) else {
            panic!("the test frame should be valid");
        };
        assert!(process(handle, &mut frame));

        video_effects_destroy(handle);
        assert!(!lock_registry().contains_key(&handle));
    }
}
