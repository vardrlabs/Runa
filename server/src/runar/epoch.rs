//! Epoch bookkeeping for one room (PROTOCOL.md amendment J).
//!
//! The server holds no keys and cannot tell a real rotation from a fake one.
//! What it can do is keep a single order: the first EPOCH_KEY for the next
//! epoch wins, and frames written under an epoch the room has left are refused
//! once the overlap window has passed. No I/O and no clock of its own, so it
//! can be unit-tested and fuzzed.
use std::time::{Duration, Instant};

/// What an EPOCH_KEY's header epoch means to the room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// One above the room's epoch and allowed now: the room has moved.
    Advanced,
    /// Equal to the room's epoch: relayed to the others as a handover.
    Handover,
    /// Anything else, or a step too soon after the last one.
    Refused,
}

/// Whether a frame that carries ciphertext may be relayed or stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    Current,
    /// The epoch just left, inside the overlap window.
    Overlap,
    Stale,
}

#[derive(Debug, Clone)]
pub struct EpochState {
    epoch: u32,
    root_epoch: u32,
    last_advance: Option<Instant>,
}

impl EpochState {
    pub fn new(epoch: u32, root_epoch: u32) -> Self {
        EpochState { epoch, root_epoch: root_epoch.min(epoch), last_advance: None }
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn root_epoch(&self) -> u32 {
        self.root_epoch
    }

    pub fn offer(&mut self, header_epoch: u32, now: Instant, min_interval: Duration) -> Offer {
        if header_epoch == self.epoch {
            return Offer::Handover;
        }
        let Some(next) = self.epoch.checked_add(1) else {
            return Offer::Refused;
        };
        if header_epoch != next {
            return Offer::Refused;
        }
        if let Some(last) = self.last_advance {
            if now.saturating_duration_since(last) < min_interval {
                return Offer::Refused;
            }
        }
        self.epoch = next;
        self.last_advance = Some(now);
        Offer::Advanced
    }

    pub fn admit(&self, frame_epoch: u32, now: Instant, overlap: Duration) -> Admit {
        if frame_epoch == self.epoch {
            return Admit::Current;
        }
        if self.epoch > 0 && frame_epoch == self.epoch - 1 {
            if let Some(last) = self.last_advance {
                if now.saturating_duration_since(last) < overlap {
                    return Admit::Overlap;
                }
            }
        }
        Admit::Stale
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(5);
    const OVERLAP: Duration = Duration::from_secs(30);

    #[test]
    fn a_new_room_is_at_epoch_zero() {
        let s = EpochState::new(0, 0);
        assert_eq!((s.epoch(), s.root_epoch()), (0, 0));
    }

    #[test]
    fn only_the_next_epoch_advances_the_room() {
        let t = Instant::now();
        let mut s = EpochState::new(0, 0);
        assert_eq!(s.offer(2, t, MIN), Offer::Refused);
        assert_eq!(s.epoch(), 0);
        assert_eq!(s.offer(1, t, MIN), Offer::Advanced);
        assert_eq!(s.epoch(), 1);
    }

    #[test]
    fn the_current_epoch_is_a_handover() {
        let t = Instant::now();
        let mut s = EpochState::new(0, 0);
        assert_eq!(s.offer(0, t, MIN), Offer::Handover);
        s.offer(1, t, MIN);
        // A second step for epoch 1 now matches the room and is relayed like a
        // handover; clients ignore a step that does not name their next epoch.
        assert_eq!(s.offer(1, t, MIN), Offer::Handover);
        assert_eq!(s.epoch(), 1);
    }

    #[test]
    fn steps_closer_than_the_minimum_interval_are_refused() {
        let t = Instant::now();
        let mut s = EpochState::new(0, 0);
        assert_eq!(s.offer(1, t, MIN), Offer::Advanced);
        assert_eq!(s.offer(2, t + Duration::from_secs(4), MIN), Offer::Refused);
        assert_eq!(s.offer(2, t + MIN, MIN), Offer::Advanced);
    }

    #[test]
    fn the_last_epoch_cannot_advance() {
        let t = Instant::now();
        let mut s = EpochState::new(u32::MAX, 0);
        assert_eq!(s.offer(u32::MAX, t, MIN), Offer::Handover);
        assert_eq!(s.offer(0, t, MIN), Offer::Refused);
        assert_eq!(s.epoch(), u32::MAX);
    }

    #[test]
    fn the_previous_epoch_is_admitted_only_inside_the_overlap() {
        let t = Instant::now();
        let mut s = EpochState::new(0, 0);
        assert_eq!(s.admit(0, t, OVERLAP), Admit::Current);
        s.offer(1, t, MIN);
        assert_eq!(s.admit(1, t, OVERLAP), Admit::Current);
        assert_eq!(s.admit(0, t + Duration::from_secs(29), OVERLAP), Admit::Overlap);
        assert_eq!(s.admit(0, t + OVERLAP, OVERLAP), Admit::Stale);
    }

    #[test]
    fn older_and_future_epochs_are_stale() {
        let t = Instant::now();
        let mut s = EpochState::new(0, 0);
        s.offer(1, t, Duration::ZERO);
        s.offer(2, t, Duration::ZERO);
        assert_eq!(s.admit(0, t, OVERLAP), Admit::Stale);
        assert_eq!(s.admit(3, t, OVERLAP), Admit::Stale);
    }

    #[test]
    fn a_restored_room_has_no_overlap() {
        let s = EpochState::new(4, 0);
        assert_eq!(s.admit(3, Instant::now(), OVERLAP), Admit::Stale);
    }

    #[test]
    fn the_root_never_passes_the_epoch() {
        assert_eq!(EpochState::new(2, 9).root_epoch(), 2);
    }
}
