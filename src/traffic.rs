//! How much data moves through the server, in total.
//!
//! This exists to answer one question before we commit to building a tunnel
//! service in v2: what does one household actually cost us per month? Without
//! numbers that decision is a guess.
//!
//! Deliberately global, never per household. "Household X moved Y MB" is
//! metadata about a specific family, which is exactly what Honmoon otherwise
//! refuses to hold. A daily total plus a count of how many households were
//! active that day gives the average — and tells us nothing about anyone.
//!
//! Counters live in memory and are flushed to `traffic_daily` on a timer, so
//! a busy relay does not take a database write per message.

use std::collections::HashSet;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

#[derive(Default)]
pub struct TrafficCounter {
    bytes_in: AtomicI64,
    bytes_out: AtomicI64,
    /// (day, household ids already counted that day). The ids never leave this
    /// process — they are here only so the same household is not counted
    /// twice. A restart loses the set and re-counts the households that
    /// reconnect, which slightly inflates the daily number; the flush interval
    /// is minutes and restarts are rare, so the average stays usable.
    seen_today: Mutex<(String, HashSet<String>)>,
}

impl TrafficCounter {
    pub fn record_in(&self, bytes: usize) {
        self.bytes_in.fetch_add(bytes as i64, Ordering::Relaxed);
    }

    pub fn record_out(&self, bytes: usize) {
        self.bytes_out.fetch_add(bytes as i64, Ordering::Relaxed);
    }

    /// Call when a household does anything. `today` is passed in rather than
    /// read from the clock so the caller controls the date format.
    pub fn record_active(&self, today: &str, household_id: &str) {
        let mut seen = self.seen_today.lock().unwrap();
        if seen.0 != today {
            *seen = (today.to_string(), HashSet::new());
        }
        seen.1.insert(household_id.to_string());
    }

    /// Byte counters since the last flush, plus how many distinct households
    /// have been active today. Bytes reset; the household set does not, so the
    /// value written to the day's row is the running total for that day.
    pub fn take(&self, today: &str) -> (i64, i64, i64) {
        let households = {
            let mut seen = self.seen_today.lock().unwrap();
            if seen.0 != today {
                *seen = (today.to_string(), HashSet::new());
            }
            seen.1.len() as i64
        };
        (
            self.bytes_in.swap(0, Ordering::Relaxed),
            self.bytes_out.swap(0, Ordering::Relaxed),
            households,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_bytes_once_and_households_once_per_day() {
        let counter = TrafficCounter::default();
        counter.record_in(100);
        counter.record_out(250);
        counter.record_active("2026-07-28", "household-a");
        counter.record_active("2026-07-28", "household-a");
        counter.record_active("2026-07-28", "household-b");

        assert_eq!(counter.take("2026-07-28"), (100, 250, 2));
        // Bytes are a delta between flushes; the household total is not.
        assert_eq!(counter.take("2026-07-28"), (0, 0, 2));
        // New day, fresh set.
        assert_eq!(counter.take("2026-07-29"), (0, 0, 0));
    }
}
