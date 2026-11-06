#![no_main]
//! `EpochState` against a model of the rules in PROTOCOL.md amendment J, under
//! an arbitrary sequence of steps, admissions and clock moves. The model is
//! two numbers (the epoch and when it last advanced) and every answer the real
//! state gives is compared with the one the model expects, not merely checked
//! for plausibility. Half the runs start at `u32::MAX - 3`, so the last epoch
//! and the overflow guard are reached.
use libfuzzer_sys::fuzz_target;
use runa_server::runar::epoch::{Admit, EpochState, Offer};
use std::time::{Duration, Instant};

const MIN: Duration = Duration::from_millis(50);
const OVERLAP: Duration = Duration::from_millis(300);

struct Model {
    epoch: u32,
    last_advance: Option<Duration>,
}

impl Model {
    fn offer(&mut self, header: u32, clock: Duration) -> Offer {
        if header == self.epoch {
            return Offer::Handover;
        }
        // checked_add: at u32::MAX there is no next epoch to step to.
        if self.epoch.checked_add(1) == Some(header) {
            let allowed = match self.last_advance {
                None => true,
                Some(t) => clock - t >= MIN,
            };
            if allowed {
                self.epoch = header;
                self.last_advance = Some(clock);
                return Offer::Advanced;
            }
        }
        Offer::Refused
    }

    fn admit(&self, frame: u32, clock: Duration) -> Admit {
        if frame == self.epoch {
            return Admit::Current;
        }
        let just_left = self.epoch > 0 && frame == self.epoch - 1;
        match self.last_advance {
            Some(t) if just_left && clock - t < OVERLAP => Admit::Overlap,
            _ => Admit::Stale,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let start_epoch = if first & 1 == 0 { 0 } else { u32::MAX - 3 };
    let start = Instant::now();
    let mut clock = Duration::ZERO;
    let mut st = EpochState::new(start_epoch, 0);
    let mut model = Model { epoch: start_epoch, last_advance: None };
    for pair in rest.chunks_exact(2) {
        let (op, arg) = (pair[0], pair[1]);
        match op % 3 {
            0 => clock += Duration::from_millis(u64::from(arg) * 4),
            1 => {
                let header = model.epoch.wrapping_add(u32::from(arg % 4)).wrapping_sub(1);
                let want = model.offer(header, clock);
                assert_eq!(st.offer(header, start + clock, MIN), want, "offer {header}");
                assert_eq!(st.epoch(), model.epoch);
            }
            _ => {
                let frame = model.epoch.wrapping_add(u32::from(arg % 4)).wrapping_sub(2);
                assert_eq!(
                    st.admit(frame, start + clock, OVERLAP),
                    model.admit(frame, clock),
                    "admit {frame}",
                );
            }
        }
        // The root is where the room started and no step moves it, and it can
        // never pass the epoch.
        assert_eq!(st.root_epoch(), 0);
        assert!(st.root_epoch() <= st.epoch());
    }
});
