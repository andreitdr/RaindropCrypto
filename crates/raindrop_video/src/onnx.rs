//! The real person segmenter: an ONNX model run by `tract`.
//!
//! Pure Rust on purpose. The one cargokit build has to produce this crate for
//! five targets with no toolchain of its own, and an inference runtime with a
//! C++ core would need linking solved separately on each of them.
//! [`crate::segmentation::Segmenter`] is the seam a faster, accelerated backend
//! comes in through later — once there is something to measure it against.
//!
//! The model is committed, so [`OnnxSegmenter::bundled`] exists — but it is
//! still conditional on `models/` holding it (see `models/README.md`, and
//! `build.rs` for the wiring), because a checkout without it should build
//! rather than fail. Everything here works on any model of the documented
//! shape, and [`OnnxSegmenter::from_bytes`] is how the tests reach it.

use tract_onnx::prelude::*;

use crate::Error;
use crate::mask::Mask;
use crate::segmentation::Segmenter;

/// The model this crate is built against. A new model is a new *name*, never an
/// edit in place — the same rule the encryption core's byte formats follow —
/// and `build.rs` holds a copy of it that has to move with this one.
pub const MODEL_FILE: &str = "selfie_segmenter_v1.onnx";

/// The square the model takes, and gives back.
pub const INPUT_SIZE: usize = 256;

/// Scaled to 0..1 per channel, which is what MediaPipe's segmenters expect.
/// A model trained on a different normalisation produces a mask that is subtly
/// wrong rather than obviously broken, so this is stated rather than assumed.
const SCALE: f32 = 1.0 / 255.0;

/// A segmenter over one loaded model.
pub struct OnnxSegmenter {
    model: TypedRunnableModel<TypedModel>,
    input: Tensor,
}

impl OnnxSegmenter {
    /// The model compiled into this build.
    ///
    /// Only exists when one is committed; until then the crate falls back to
    /// [`crate::segmentation::CentreOvalSegmenter`] and says so through
    /// [`crate::Effects::backend`].
    #[cfg(bundled_model)]
    pub fn bundled() -> Result<Self, Error> {
        Self::from_bytes(include_bytes!(concat!("../models/", "selfie_segmenter_v1.onnx")))
    }

    /// Loads a model from ONNX bytes.
    ///
    /// The shape is fixed here rather than read from the model, because a model
    /// of an unexpected shape should be refused at load — when it can be
    /// reported — and not produce a quietly wrong mask on every frame.
    pub fn from_bytes(onnx: &[u8]) -> Result<Self, Error> {
        let shape = tvec!(1, INPUT_SIZE, INPUT_SIZE, 3);

        let model = tract_onnx::onnx()
            .model_for_read(&mut std::io::Cursor::new(onnx))
            .map_err(|_| Error::Segmentation("the model could not be read as ONNX"))?
            .with_input_fact(0, f32::fact(shape.clone()).into())
            .map_err(|_| Error::Segmentation("the model does not take a 256x256 RGB image"))?
            .into_optimized()
            .map_err(|_| Error::Segmentation("the model could not be optimised"))?
            .into_runnable()
            .map_err(|_| Error::Segmentation("the model could not be prepared to run"))?;

        // One buffer, reused for every frame: a fresh allocation per mask would
        // be the largest one this crate makes, several times a second.
        let input =
            Tensor::zero::<f32>(&shape).map_err(|_| Error::Segmentation("the input buffer could not be allocated"))?;

        Ok(Self { model, input })
    }
}

impl Segmenter for OnnxSegmenter {
    fn name(&self) -> &'static str {
        "onnx"
    }

    fn input_size(&self) -> usize {
        INPUT_SIZE
    }

    fn segment(&mut self, rgb: &[u8]) -> Result<Mask, Error> {
        let pixels = INPUT_SIZE * INPUT_SIZE * 3;
        if rgb.len() < pixels {
            return Err(Error::Segmentation("the input square was the wrong size"));
        }

        let buffer = self
            .input
            .as_slice_mut::<f32>()
            .map_err(|_| Error::Segmentation("the input buffer is the wrong type"))?;

        for (slot, byte) in buffer.iter_mut().zip(rgb[..pixels].iter()) {
            *slot = f32::from(*byte) * SCALE;
        }

        let outputs = self
            .model
            .run(tvec!(self.input.clone().into()))
            .map_err(|_| Error::Segmentation("the model failed to run"))?;

        let output = outputs
            .first()
            .ok_or(Error::Segmentation("the model returned nothing"))?
            .to_array_view::<f32>()
            .map_err(|_| Error::Segmentation("the model's output is not confidences"))?;

        let confidences = output
            .as_slice()
            .ok_or(Error::Segmentation("the model's output is not contiguous"))?;

        if confidences.len() < INPUT_SIZE * INPUT_SIZE {
            return Err(Error::Segmentation("the model returned a smaller mask than its input"));
        }

        let mut mask = Mask::new(INPUT_SIZE, INPUT_SIZE);
        for (alpha, confidence) in mask.alpha.iter_mut().zip(confidences.iter()) {
            *alpha = (confidence * 255.0).round().clamp(0.0, 255.0) as u8;
        }

        Ok(mask)
    }
}

/// Whether a segmentation model is compiled into this build.
///
/// The UI gates the whole effects picker on this rather than on the platform: a
/// build without the model would find the wrong shape, and offering an effect
/// that blurs the wrong thing is worse than not offering it.
pub fn model_bundled() -> bool {
    cfg!(bundled_model)
}

/// What the segmenter in use is called, without constructing one.
pub fn best_name() -> &'static str {
    if cfg!(bundled_model) { "onnx" } else { "centre-oval" }
}

/// The best segmenter this build has.
///
/// The real model when one is committed, and the deterministic fallback
/// otherwise — so a build without the model is a build with a weaker effect,
/// not a build without a camera.
pub fn best() -> Box<dyn Segmenter> {
    #[cfg(bundled_model)]
    if let Ok(segmenter) = OnnxSegmenter::bundled() {
        return Box::new(segmenter);
    }

    Box::new(crate::segmentation::CentreOvalSegmenter::default())
}
