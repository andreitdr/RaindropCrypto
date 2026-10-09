//! Compiles the segmentation model in when it is present.
//!
//! The model is a binary artefact with its own licence and provenance, fetched
//! and converted by the command in `models/README.md`. Until it is committed,
//! `cfg(bundled_model)` is off and `OnnxSegmenter::bundled` does not exist — so
//! the crate, its tests and the whole client build work without it, and the
//! real segmenter appears the moment the file is dropped in.

use std::path::Path;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(bundled_model)");

    let model = Path::new("models").join(raindrop_model_name());
    println!("cargo::rerun-if-changed={}", model.display());

    if model.exists() {
        println!("cargo::rustc-cfg=bundled_model");
    }
}

/// Kept in step with `segmentation::onnx::MODEL_FILE` by hand: a build script
/// cannot read the crate it builds. A new model is a new *name*, never an edit
/// in place, the same rule the encryption core's formats follow.
fn raindrop_model_name() -> &'static str {
    "selfie_segmenter_v1.onnx"
}
