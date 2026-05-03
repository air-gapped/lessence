//! Reproducible-build helpers for embedded timestamps.

use chrono::{DateTime, Utc};

/// Timestamp to embed in generated output (e.g. the markdown report header).
///
/// Honors the [`SOURCE_DATE_EPOCH`] environment variable when set to a
/// valid Unix epoch — the Reproducible Builds standard. Useful for
/// deterministic output in snapshot tests, regression-check tooling, and
/// reproducible-build pipelines. Falls back to wall-clock `Utc::now()`
/// otherwise.
///
/// [`SOURCE_DATE_EPOCH`]: https://reproducible-builds.org/specs/source-date-epoch/
pub fn timestamp() -> DateTime<Utc> {
    resolve_timestamp(std::env::var("SOURCE_DATE_EPOCH").ok().as_deref())
}

/// Pure resolver — parses the env value if present, falls back to
/// `Utc::now()` otherwise. Split from `timestamp()` so the env-handling
/// logic can be unit-tested without mutating process-global state (which
/// `unsafe_code = "forbid"` rules out anyway in Rust 2024).
fn resolve_timestamp(epoch_str: Option<&str>) -> DateTime<Utc> {
    if let Some(s) = epoch_str
        && let Ok(epoch) = s.parse::<i64>()
        && let Some(t) = DateTime::from_timestamp(epoch, 0)
    {
        return t;
    }
    Utc::now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_uses_wall_clock() {
        let before = Utc::now();
        let t = resolve_timestamp(None);
        let after = Utc::now();
        assert!(
            t >= before && t <= after,
            "wall-clock timestamp out of bounds: {t}"
        );
    }

    #[test]
    fn epoch_zero_returns_unix_epoch() {
        let t = resolve_timestamp(Some("0"));
        assert_eq!(
            t.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn explicit_epoch_returns_that_instant() {
        // 1234567890 = 2009-02-13T23:31:30Z, the canonical fixture
        let t = resolve_timestamp(Some("1234567890"));
        assert_eq!(
            t.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "2009-02-13T23:31:30Z"
        );
    }

    #[test]
    fn non_numeric_falls_back_to_wall_clock() {
        let before = Utc::now();
        let t = resolve_timestamp(Some("not-a-number"));
        let after = Utc::now();
        assert!(
            t >= before && t <= after,
            "fallback timestamp out of bounds: {t}"
        );
    }

    #[test]
    fn empty_string_falls_back_to_wall_clock() {
        let before = Utc::now();
        let t = resolve_timestamp(Some(""));
        let after = Utc::now();
        assert!(t >= before && t <= after);
    }

    #[test]
    fn negative_epoch_pre_1970_works() {
        // SOURCE_DATE_EPOCH spec is non-negative, but chrono accepts negative
        // values (pre-1970) — we don't reject them because we'd have to add
        // logic that the spec doesn't require, and a negative value is still
        // a valid instant for embedding.
        let t = resolve_timestamp(Some("-1"));
        assert_eq!(
            t.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "1969-12-31T23:59:59Z"
        );
    }

    #[test]
    fn out_of_range_epoch_falls_back() {
        // i64::MAX seconds is way past chrono's representable range
        let before = Utc::now();
        let t = resolve_timestamp(Some(&i64::MAX.to_string()));
        let after = Utc::now();
        assert!(
            t >= before && t <= after,
            "should fall back when out of range"
        );
    }
}
