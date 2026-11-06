#![no_main]
//! `EpochState` under an arbitrary sequence of steps, admissions and clock
//! moves. The invariants are properties of the sequence: the epoch only ever
//! moves up by one, never twice inside the minimum interval, and the previous
//! epoch is admitted only inside the overlap after an advance.
use libfuzzer_sys::fuzz_target;
use runa_server::runar::epoch::{Admit, EpochState, Offer};
use std::time::{Duration, Instant};

const MIN: Duration = Duration::from_millis(50);
const OVERLAP: Duration = Duration::from_millis(300);

fuzz_target!(|data: &[u8]| {
    let start = Instant::now();
    let mut clock = Duration::ZERO;
    let mut st = EpochState::new(0, 0);
    let mut last_advanced_at: Option<Duration> = None;
    let mut i = 0;
    while i + 2 <= data.len() {
        let (op, arg) = (data[i], data[i + 1]);
        i += 2;
        match op % 3 {
            0 => clock += Duration::from_millis(u64::from(arg) * 4),
            1 => {
                let before = st.epoch();
                let header = before.wrapping_add(u32::from(arg % 4)).wrapping_sub(1);
                match st.offer(header, start + clock, MIN) {
                    Offer::Advanced => {
                        assert_eq!(header, before + 1);
                        assert_eq!(st.epoch(), before + 1);
                        if let Some(t) = last_advanced_at {
                            assert!(clock - t >= MIN, "two steps inside the minimum interval");
                        }
                        last_advanced_at = Some(clock);
                    }
                    Offer::Handover => {
                        assert_eq!(header, before);
                        assert_eq!(st.epoch(), before);
                    }
                    Offer::Refused => assert_eq!(st.epoch(), before),
                }
            }
            _ => {
                let e = st.epoch();
                let frame = e.wrapping_add(u32::from(arg % 4)).wrapping_sub(2);
                match st.admit(frame, start + clock, OVERLAP) {
                    Admit::Current => assert_eq!(frame, e),
                    Admit::Overlap => {
                        assert_eq!(frame.wrapping_add(1), e);
                        let t = last_advanced_at.expect("overlap without an advance");
                        assert!(clock - t < OVERLAP);
                    }
                    Admit::Stale => assert_ne!(frame, e),
                }
            }
        }
        assert_eq!(st.root_epoch(), 0);
    }
});
