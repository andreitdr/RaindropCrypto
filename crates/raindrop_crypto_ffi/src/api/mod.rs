//! Everything under this module is exposed to Dart by flutter_rust_bridge_codegen.

pub mod attachment;
pub mod session;
pub mod video;

#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}
