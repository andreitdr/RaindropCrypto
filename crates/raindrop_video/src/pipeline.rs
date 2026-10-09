//! What happens to each frame, and what happens when that takes too long.
//!
//! Two clocks, deliberately out of step:
//!
//! - **Every frame** is composited, on the capture thread, against whatever
//!   mask is current. That has to be fast and must never block.
//! - **Some frames** also hand a small RGB square to the segmentation worker.
//!   How often is `mask_hz`, independent of the frame rate, because
//!   segmentation is an order of magnitude dearer than compositing and a person
//!   does not move far in 60ms.
//!
//! The capture thread never waits for a mask. It uses the newest one that has
//! arrived, which is what keeps a slow segmenter from dropping frames — it
//! makes the mask lag, which [`crate::mask::SMOOTHING`] already covers for.

use std::sync::mpsc::{Receiver, Sender, SyncSender, TryRecvError, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::Error;
use crate::mask::{Mask, SMOOTHING};
use crate::segmentation::Segmenter;

/// A clock, so the degradation ladder can be tested without waiting.
pub trait TimeSource: Send {
    fn now(&self) -> Duration;
}

/// The real clock.
pub struct SystemTime {
    start: std::time::Instant,
}

impl Default for SystemTime {
    fn default() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }
}

impl TimeSource for SystemTime {
    fn now(&self) -> Duration {
        self.start.elapsed()
    }
}

/// The segmentation worker: one thread, one mask in flight.
///
/// The channel holds exactly one request. If the worker is still busy the
/// capture thread's offer is simply declined — a queue would mean compositing
/// against masks that are already stale, and under sustained overload would
/// grow without bound.
pub struct MaskWorker {
    requests: SyncSender<Vec<u8>>,
    masks: Receiver<Mask>,
    thread: Option<JoinHandle<()>>,
    input_size: usize,
    name: &'static str,
}

impl MaskWorker {
    pub fn spawn(mut segmenter: Box<dyn Segmenter>) -> Self {
        let input_size = segmenter.input_size();
        let name = segmenter.name();

        let (requests, incoming) = sync_channel::<Vec<u8>>(1);
        let (outgoing, masks) = std::sync::mpsc::channel::<Mask>();

        let thread = std::thread::Builder::new()
            .name("raindrop-video-mask".into())
            .spawn(move || worker(&mut *segmenter, &incoming, &outgoing))
            .ok();

        Self {
            requests,
            masks,
            thread,
            input_size,
            name,
        }
    }

    pub fn input_size(&self) -> usize {
        self.input_size
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Offers a square to segment. False when the worker is still busy, which
    /// is not an error — the frame is composited against the previous mask.
    pub fn offer(&self, rgb: Vec<u8>) -> bool {
        self.requests.try_send(rgb).is_ok()
    }

    /// The newest mask the worker has finished, draining any older ones.
    pub fn take_newest(&self) -> Option<Mask> {
        let mut newest = None;
        loop {
            match self.masks.try_recv() {
                Ok(mask) => newest = Some(mask),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return newest,
            }
        }
    }
}

impl Drop for MaskWorker {
    fn drop(&mut self) {
        // Dropping the sender ends the worker's loop; joining it means the
        // segmenter is really gone before the model it borrowed is freed.
        let (dead, _) = sync_channel::<Vec<u8>>(1);
        let live = std::mem::replace(&mut self.requests, dead);
        drop(live);

        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn worker(segmenter: &mut dyn Segmenter, incoming: &Receiver<Vec<u8>>, outgoing: &Sender<Mask>) {
    while let Ok(rgb) = incoming.recv() {
        // A segmenter that fails is a mask that did not arrive. The previous
        // one stays current, which is strictly better than a blank mask: a
        // blank one would un-blur the background for a frame.
        if let Ok(mask) = segmenter.segment(&rgb)
            && outgoing.send(mask).is_err()
        {
            return;
        }
    }
}

/// How current the mask is, and how often to ask for a new one.
pub struct MaskClock {
    /// The mask every frame is composited against. Always present, so there is
    /// no "no mask yet" branch in the per-frame path.
    pub current: Mask,
    /// Whether a real mask has ever arrived. Until one has, `current` is opaque
    /// and the frame passes through unchanged — the alternative is blurring a
    /// person who has not been found yet.
    pub warm: bool,
    pub masks: u64,
    interval: Duration,
    next: Duration,
}

impl MaskClock {
    pub fn new(hz: f32) -> Self {
        Self {
            current: Mask::opaque(1, 1),
            warm: false,
            masks: 0,
            interval: interval_for(hz),
            next: Duration::ZERO,
        }
    }

    pub fn set_rate(&mut self, hz: f32) {
        self.interval = interval_for(hz);
    }

    pub fn due(&self, now: Duration) -> bool {
        now >= self.next
    }

    pub fn asked(&mut self, now: Duration) {
        self.next = now + self.interval;
    }

    /// Folds a freshly finished mask into the current one.
    pub fn arrived(&mut self, mask: Mask) {
        self.masks += 1;

        if self.warm {
            self.current.smooth_towards(&mask, SMOOTHING);
        } else {
            // Nothing to smooth against, and smoothing against the opaque
            // placeholder would start every call with one half-blurred frame.
            self.current = mask;
            self.warm = true;
        }
    }
}

fn interval_for(hz: f32) -> Duration {
    if hz <= 0.0 {
        return Duration::MAX;
    }

    Duration::from_secs_f32((1.0 / hz).clamp(0.001, 10.0))
}

/// What the pipeline gives up, in order, when it cannot keep up.
///
/// In the crate rather than the UI because only here is the real cost known,
/// and because the decision has to be made inside the frame loop. The order is
/// chosen so the picture degrades before the motion does: a background that
/// updates less often, then a coarser blur, and only as a last resort no effect
/// at all. Dropping frames is never one of the steps.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Degradation {
    #[default]
    None,
    /// Segmentation at half the configured rate.
    HalfMaskRate,
    /// Half rate, and the blur computed at quarter resolution.
    CoarseBlur,
    /// The effect switched off. Reported to the UI so it can say so.
    Off,
}

impl Degradation {
    pub fn worse(self) -> Self {
        match self {
            Self::None => Self::HalfMaskRate,
            Self::HalfMaskRate => Self::CoarseBlur,
            Self::CoarseBlur | Self::Off => Self::Off,
        }
    }
}

/// Decides when to step down the ladder.
///
/// Sustained overload, not a single slow frame: a first frame that touches cold
/// caches, or one unlucky scheduling hiccup, must not permanently turn the
/// effect off. So it takes [`Self::RUN`] consecutive frames over twice the
/// budget, and any frame inside budget resets the count.
pub struct Budget {
    over: u32,
    level: Degradation,
    budget: Duration,
}

impl Budget {
    /// How many consecutive overruns before stepping down.
    pub const RUN: u32 = 30;

    pub fn new(budget: Duration) -> Self {
        Self {
            over: 0,
            level: Degradation::None,
            budget,
        }
    }

    pub fn level(&self) -> Degradation {
        self.level
    }

    /// Records how long one frame took. Returns true when the level changed.
    pub fn frame_took(&mut self, elapsed: Duration) -> bool {
        if elapsed <= self.budget * 2 {
            self.over = 0;
            return false;
        }

        self.over += 1;
        if self.over < Self::RUN {
            return false;
        }

        self.over = 0;
        let worse = self.level.worse();
        if worse == self.level {
            return false;
        }

        self.level = worse;
        true
    }
}

/// An error worth reporting from the worker rather than swallowing.
pub fn unavailable(reason: &'static str) -> Error {
    Error::Segmentation(reason)
}
