//! The Flutter binding for [`raindrop_crypto`]. Only `api` is hand-written; `frb_generated` is
//! produced by `flutter_rust_bridge_codegen generate`, run from `RaindropClient/`.

pub mod api;
pub mod c_api;
mod frb_generated;
#[cfg(target_os = "android")]
pub mod jni_api;
