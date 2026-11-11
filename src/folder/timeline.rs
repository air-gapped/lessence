//! Per-group timeline: how a group's members are spread over time.
//!
//! Folding keeps a group's count and its first and last timestamp, so
//! "09:00 → 17:00, 8,000 lines" may be steady all day or one burst at 16:55.
//! This gives back the spread as counts per time bucket, on the same grid as
//! the log-wide histogram the briefing emits, so the two compare index by
//! index. Description only: counts, and one fixed rule (`bunched_run`) for
//! when the text marker says where most of a group's lines fell.
//!
//! No timestamp is parsed here. Every line's epoch second is computed once,
//! for the log-wide histogram (`FoldingStats::record_span`), and that value
//! is what a group records.
//!
//! Memory: a group with no timestamped member holds nothing; one with a
//! single one holds that epoch inline; counters are allocated at the second.
//! They are collected the way `HistogramBuilder` collects the log-wide ones —
//! keyed by `epoch / width`, `width` doubling whenever a group holds more
//! than `HISTOGRAM_BUCKET_CAP` keys — so a group never holds more than that
//! many. The log-wide grid is only known at the end, and re-binning onto it
//! is exact: a group's keys are a subset of the log-wide builder's at the
//! same width, so the group's width can never pass the builder's, and
//! coarsening a group key to the builder's width yields exactly the key the
//! builder holds that line under; both are then placed by the same
//! `Grid::index`. Every display bucket of a group is therefore a sum of
//! lines the log-wide bucket also counts.

use crate::briefing::{Grid, HISTOGRAM_BUCKET_CAP};
use serde::Serialize;

/// A group's timestamped members, as compactly as their number allows.
#[derive(Debug, Default)]
pub(super) enum Timeline {
    /// No member carried a timestamp that places on a clock.
    #[default]
    Empty,
    /// Exactly one did: its epoch, held inline.
    One(i64),
    /// Two or more: bucketed counts.
    Many(Box<Counts>),
}

/// Bucketed member counts, keyed by `epoch.div_euclid(width)`, sorted by key.
#[derive(Debug, Clone)]
pub(super) struct Counts {
    width: u64,
    keys: Vec<(i64, u64)>,
    min: i64,
    max: i64,
    total: u64,
}

impl Counts {
    fn new(epoch: i64) -> Self {
        Self {
            width: 1,
            keys: vec![(epoch, 1)],
            min: epoch,
            max: epoch,
            total: 1,
        }
    }

    fn record(&mut self, epoch: i64) {
        self.min = self.min.min(epoch);
        self.max = self.max.max(epoch);
        self.total += 1;
        let key = epoch.div_euclid(self.width as i64);
        // Lines arrive mostly in time order: the last key or a new one past
        // it is the common case, a binary search the rest.
        match self.keys.last_mut() {
            Some((last, count)) if *last == key => *count += 1,
            Some((last, _)) if *last < key => self.keys.push((key, 1)),
            _ => match self.keys.binary_search_by_key(&key, |&(k, _)| k) {
                Ok(at) => self.keys[at].1 += 1,
                Err(at) => self.keys.insert(at, (key, 1)),
            },
        }
        self.bound();
    }

    /// Double the width until the key count is back under the cap.
    fn bound(&mut self) {
        while self.keys.len() > HISTOGRAM_BUCKET_CAP {
            self.halve();
        }
    }

    /// Double the width once, merging keys that now coincide. `div_euclid`
    /// is monotone, so the keys stay sorted and equal ones are adjacent.
    fn halve(&mut self) {
        self.width *= 2;
        let mut out: Vec<(i64, u64)> = Vec::with_capacity(self.keys.len() / 2 + 1);
        for &(key, count) in &self.keys {
            let key = key.div_euclid(2);
            match out.last_mut() {
                Some((last, c)) if *last == key => *c += count,
                _ => out.push((key, count)),
            }
        }
        self.keys = out;
    }

    fn merge(&mut self, mut other: Counts) {
        while self.width < other.width {
            self.halve();
        }
        while other.width < self.width {
            other.halve();
        }
        let mut out = Vec::with_capacity(self.keys.len() + other.keys.len());
        let (mut a, mut b) = (self.keys.iter().peekable(), other.keys.iter().peekable());
        loop {
            match (a.peek(), b.peek()) {
                (Some(&&(ka, ca)), Some(&&(kb, cb))) => match ka.cmp(&kb) {
                    std::cmp::Ordering::Equal => {
                        out.push((ka, ca + cb));
                        a.next();
                        b.next();
                    }
                    std::cmp::Ordering::Less => {
                        out.push((ka, ca));
                        a.next();
                    }
                    std::cmp::Ordering::Greater => {
                        out.push((kb, cb));
                        b.next();
                    }
                },
                (Some(&&x), None) => {
                    out.push(x);
                    a.next();
                }
                (None, Some(&&x)) => {
                    out.push(x);
                    b.next();
                }
                (None, None) => break,
            }
        }
        self.keys = out;
        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);
        self.total += other.total;
        self.bound();
    }

    /// The display bucket a collected key lands in.
    fn place(&self, grid: &Grid, key: i64) -> usize {
        let collected = grid.collected_seconds.max(1);
        if self.width <= collected {
            // Both widths are powers of two: coarsen to the builder's
            // width, then place exactly as the builder does.
            let ratio = (collected / self.width) as i64;
            grid.index(key.div_euclid(ratio))
        } else {
            // Unreachable by the subset argument in the module doc;
            // placed by its start rather than panicking.
            grid.index_at(key * self.width as i64)
        }
    }

    /// The counts on `grid`'s display buckets.
    fn on_grid(&self, grid: &Grid) -> Vec<u64> {
        let mut buckets = vec![0u64; grid.len];
        for &(key, count) in &self.keys {
            buckets[self.place(grid, key)] += count;
        }
        buckets
    }

    /// The earliest and latest second the members placed in display
    /// buckets `first..=last` can carry, from the group's own (finer)
    /// keys, tightened to its earliest and latest member.
    fn run_bounds(&self, grid: &Grid, first: usize, last: usize) -> (i64, i64) {
        let width = self.width as i64;
        let mut lo = i64::MAX;
        let mut hi = i64::MIN;
        for &(key, _) in &self.keys {
            if (first..=last).contains(&self.place(grid, key)) {
                lo = lo.min(key * width);
                hi = hi.max(key * width + width - 1);
            }
        }
        let from = lo.max(self.min);
        (from, hi.min(self.max).max(from))
    }
}

impl Timeline {
    /// Record one member's epoch second.
    pub(super) fn record(&mut self, epoch: i64) {
        match self {
            Timeline::Empty => *self = Timeline::One(epoch),
            Timeline::One(first) => {
                let mut counts = Counts::new(*first);
                counts.record(epoch);
                *self = Timeline::Many(Box::new(counts));
            }
            Timeline::Many(counts) => counts.record(epoch),
        }
    }

    /// Fold another group's timeline into this one (render-time merge).
    pub(super) fn absorb(&mut self, other: Timeline) {
        match other {
            Timeline::Empty => {}
            Timeline::One(epoch) => self.record(epoch),
            Timeline::Many(mut counts) => match std::mem::take(self) {
                Timeline::Empty => *self = Timeline::Many(counts),
                Timeline::One(epoch) => {
                    counts.record(epoch);
                    *self = Timeline::Many(counts);
                }
                Timeline::Many(mut mine) => {
                    mine.merge(*counts);
                    *self = Timeline::Many(mine);
                }
            },
        }
    }

    /// The group's buckets on the log-wide grid, and where it bunches.
    /// `None` below 3 timestamped members or when they all fall in one
    /// bucket: `first_seen`/`last_seen` already say everything then.
    /// `dated` is whether the group's stamps carry their own year.
    pub(super) fn view(&self, grid: &Grid, dated: bool) -> Option<TimelineView> {
        let Timeline::Many(counts) = self else {
            return None;
        };
        if counts.total < 3 {
            return None;
        }
        let buckets = counts.on_grid(grid);
        if buckets.iter().filter(|&&c| c > 0).count() < 2 {
            return None;
        }
        let bunched = bunched_run(&buckets).and_then(|(first, last, members)| {
            let (lo, hi) = counts.run_bounds(grid, first, last);
            // The same quarter, in seconds: the run's own members must also
            // span at most a quarter of the group's. On a log whose lines
            // are not in time order the grid clamps everything before its
            // first line into bucket 0, and a run of few buckets can then
            // hold members from across the whole span; it says nothing.
            if (hi - lo).saturating_mul(4) > counts.max - counts.min {
                return None;
            }
            let (from, to) = run_times(lo, hi, counts.min, counts.max, dated);
            Some(Bunched {
                first_bucket: first,
                last_bucket: last,
                members,
                pct: members * 100 / counts.total,
                from,
                to,
            })
        });
        Some(TimelineView {
            bucket_seconds: grid.bucket_seconds as u64,
            buckets,
            bunched,
        })
    }
}

/// What a group's `time_range` gains in JSON.
#[derive(Debug, Clone)]
pub(super) struct TimelineView {
    pub bucket_seconds: u64,
    pub buckets: Vec<u64>,
    pub bunched: Option<Bunched>,
}

/// The run of buckets a bunched group's lines fell in (`bunched_run`).
#[derive(Debug, Clone, Serialize)]
pub(super) struct Bunched {
    /// First and last display bucket of the run, inclusive.
    pub first_bucket: usize,
    pub last_bucket: usize,
    /// Timestamped members in the run.
    pub members: u64,
    /// `members` as a whole percentage of the group's timestamped members,
    /// rounded down, so it never claims more than the run holds.
    pub pct: u64,
    /// When the run starts and ends, written as the clause writes them.
    pub from: String,
    pub to: String,
}

impl Bunched {
    /// The text clause: `98% in 16:55–16:58`.
    pub(super) fn clause(&self) -> String {
        crate::briefing::bunched_clause(self.pct, &self.from, &self.to)
    }
}

/// The bunched rule, fixed: a group of at least 10 timestamped members
/// whose own span (first to last non-empty bucket) covers at least 4
/// buckets is bunched when the shortest run of consecutive buckets holding
/// at least 90% of those members covers at most a quarter of that span.
/// Returns the run as `(first, last, members)`. Among runs of the shortest
/// length the one holding most members wins, then the earliest.
pub(super) fn bunched_run(buckets: &[u64]) -> Option<(usize, usize, u64)> {
    const MIN_MEMBERS: u64 = 10;
    const MIN_SPAN: usize = 4;
    let total: u64 = buckets.iter().sum();
    if total < MIN_MEMBERS {
        return None;
    }
    let first = buckets.iter().position(|&c| c > 0)?;
    let last = buckets.iter().rposition(|&c| c > 0)?;
    let span = last - first + 1;
    if span < MIN_SPAN {
        return None;
    }
    let mut best: Option<(usize, usize, u64)> = None;
    for start in first..=last {
        let mut sum = 0u64;
        for (end, &count) in buckets.iter().enumerate().take(last + 1).skip(start) {
            sum += count;
            // At least 90%, in integers: 10·sum ≥ 9·total.
            if sum * 10 >= total * 9 {
                let len = end - start + 1;
                let better = match best {
                    None => true,
                    Some((s, e, m)) => {
                        let best_len = e - s + 1;
                        len < best_len || (len == best_len && sum > m)
                    }
                };
                if better {
                    best = Some((start, end, sum));
                }
                break;
            }
        }
    }
    let (start, end, members) = best?;
    ((end - start + 1) * 4 <= span).then_some((start, end, members))
}

/// The run's start `from` and end `to` (epoch seconds) as the clause
/// writes them, for a group whose members run from `min` to `max`. Clock
/// time only when the group's members all share one date; otherwise the
/// date too, with the year only when the log's stamps carry one. Minutes,
/// unless the two ends would then read the same.
fn run_times(from: i64, to: i64, min: i64, max: i64, dated: bool) -> (String, String) {
    let day = |e: i64| e.div_euclid(86_400);
    let date = if day(min) == day(max) {
        ""
    } else if dated {
        "%Y-%m-%d "
    } else {
        "%m-%d "
    };
    let show = |e: i64, secs: bool, date: &str| {
        let fmt = format!("{date}{}", if secs { "%H:%M:%S" } else { "%H:%M" });
        chrono::DateTime::from_timestamp(e, 0)
            .map_or_else(|| e.to_string(), |dt| dt.format(&fmt).to_string())
    };
    let secs = show(from, false, date) == show(to, false, date);
    // A run inside one day names that day once: `09-09 16:00–16:05`.
    let to_date = if day(from) == day(to) { "" } else { date };
    (show(from, secs, date), show(to, secs, to_date))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grid(origin: i64, bucket_seconds: i64, len: usize) -> Grid {
        Grid {
            origin,
            bucket_seconds,
            len,
            collected_seconds: 1,
        }
    }

    #[test]
    fn exactly_ninety_percent_in_one_bucket_of_four_is_bunched() {
        assert_eq!(bunched_run(&[9, 0, 0, 1]), Some((0, 0, 9)));
    }

    #[test]
    fn just_under_ninety_percent_is_not_bunched_in_one_bucket() {
        // 89 of 100 in one bucket: the 90% run needs two buckets, and two
        // of a four-bucket span is more than a quarter.
        assert_eq!(bunched_run(&[89, 0, 0, 11]), None);
        assert_eq!(bunched_run(&[89, 1, 0, 10]), None);
    }

    #[test]
    fn a_run_of_exactly_a_quarter_of_the_span_is_bunched() {
        // Span 8, run 2.
        assert_eq!(bunched_run(&[1, 0, 0, 0, 0, 0, 5, 5]), Some((6, 7, 10)));
        // Span 7, run 2: over a quarter.
        assert_eq!(bunched_run(&[1, 0, 0, 0, 0, 5, 5]), None);
    }

    #[test]
    fn three_buckets_are_too_short_a_span_and_four_are_enough() {
        assert_eq!(bunched_run(&[19, 0, 1]), None);
        assert_eq!(bunched_run(&[19, 0, 0, 1]), Some((0, 0, 19)));
        // The span is the group's own, not the grid's.
        assert_eq!(bunched_run(&[0, 0, 19, 0, 1, 0, 0]), None);
    }

    #[test]
    fn nine_members_are_too_few_and_ten_are_enough() {
        assert_eq!(bunched_run(&[8, 0, 0, 1]), None);
        assert_eq!(bunched_run(&[9, 0, 0, 1]), Some((0, 0, 9)));
    }

    #[test]
    fn a_steady_group_is_not_bunched() {
        assert_eq!(bunched_run(&[5; 24]), None);
    }

    #[test]
    fn ties_go_to_the_fuller_run_then_the_earliest() {
        assert_eq!(
            bunched_run(&[45, 0, 0, 0, 0, 0, 0, 55]),
            None,
            "neither single bucket holds 90%"
        );
        assert_eq!(
            bunched_run(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0
            ]),
            Some((20, 20, 30))
        );
        // Two single buckets both reach 90% only if one holds it; with
        // equal halves of 50/50 none does, and with 95/5 the 95 wins.
        assert_eq!(bunched_run(&[95, 0, 0, 5]), Some((0, 0, 95)));
        assert_eq!(bunched_run(&[5, 0, 0, 95]), Some((3, 3, 95)));
    }

    #[test]
    fn of_two_shortest_runs_holding_the_same_the_earlier_wins() {
        // 104 members, 90% is 93.6. Buckets 1-2 and 2-3 both hold 95.
        let buckets = [1, 5, 90, 5, 0, 0, 0, 0, 0, 0, 0, 3];
        assert_eq!(bunched_run(&buckets), Some((1, 2, 95)));
    }

    #[test]
    fn of_two_shortest_runs_the_fuller_wins() {
        // Buckets 1-2 hold 94, buckets 2-3 hold 96.
        let buckets = [1, 4, 90, 6, 0, 0, 0, 0, 0, 0, 0, 3];
        assert_eq!(bunched_run(&buckets), Some((2, 3, 96)));
    }

    fn counts(epochs: &[i64]) -> Counts {
        let mut c = Counts::new(epochs[0]);
        for &e in &epochs[1..] {
            c.record(e);
        }
        c
    }

    #[test]
    fn keys_stay_sorted_and_counted_when_lines_arrive_out_of_order() {
        let c = counts(&[200, 100, 200]);
        assert_eq!(c.keys, vec![(100, 1), (200, 2)]);
        assert_eq!((c.min, c.max, c.total), (100, 200, 3));
    }

    #[test]
    fn the_width_doubles_only_past_the_cap() {
        let cap = HISTOGRAM_BUCKET_CAP as i64;
        let mut c = counts(&(0..cap).collect::<Vec<_>>());
        assert_eq!((c.width, c.keys.len()), (1, HISTOGRAM_BUCKET_CAP));
        c.record(cap);
        assert_eq!((c.width, c.keys.len()), (2, HISTOGRAM_BUCKET_CAP / 2 + 1));
    }

    #[test]
    fn merging_adds_counts_on_a_shared_key_and_keeps_the_width() {
        let mut a = counts(&[10, 10, 20]);
        a.merge(counts(&[10, 10, 10, 30]));
        assert_eq!(a.width, 1);
        assert_eq!(a.keys, vec![(10, 5), (20, 1), (30, 1)]);
        assert_eq!((a.min, a.max, a.total), (10, 30, 7));
    }

    #[test]
    fn a_finer_group_is_placed_where_the_log_wide_builder_placed_the_line() {
        // The builder holds second 127 under key 1 at width 64, which
        // starts at second 64: display bucket 0, not the bucket 127 is in.
        let c = counts(&[127, 127, 130]);
        let g = Grid {
            origin: 0,
            bucket_seconds: 100,
            len: 24,
            collected_seconds: 64,
        };
        assert_eq!(c.on_grid(&g)[0], 2);
        assert_eq!(c.on_grid(&g)[1], 1);
    }

    #[test]
    fn a_group_coarser_than_the_grid_is_placed_by_its_keys_start() {
        let mut c = counts(&[200, 201]);
        c.halve();
        c.halve();
        assert_eq!((c.width, c.keys.clone()), (4, vec![(50, 2)]));
        assert_eq!(c.on_grid(&grid(0, 100, 24))[2], 2);
    }

    #[test]
    fn run_bounds_are_the_seconds_the_runs_keys_cover() {
        let mut c = counts(&[100, 205, 207, 1000]);
        c.halve();
        c.halve();
        assert_eq!(c.keys, vec![(25, 1), (51, 2), (250, 1)]);
        let g = Grid {
            origin: 0,
            bucket_seconds: 100,
            len: 24,
            collected_seconds: 4,
        };
        // Key 51 at width 4 covers seconds 204..=207.
        assert_eq!(c.run_bounds(&g, 2, 2), (204, 207));
        // Tightened to the group's earliest and latest member.
        assert_eq!(c.run_bounds(&g, 0, 23), (100, 1000));
    }

    #[test]
    fn three_members_in_two_buckets_have_a_view() {
        let mut t = Timeline::default();
        t.record(10);
        t.record(20);
        t.record(130);
        let v = t.view(&grid(0, 60, 24), true).unwrap();
        assert_eq!((v.buckets[0], v.buckets[2]), (2, 1));
    }

    #[test]
    fn a_run_spanning_exactly_a_quarter_of_the_groups_seconds_is_bunched() {
        // Nine members over seconds 0..=25, one at 100: 25 × 4 = 100.
        let mut t = Timeline::default();
        for _ in 0..5 {
            t.record(0);
        }
        for _ in 0..4 {
            t.record(25);
        }
        t.record(100);
        let b = t.view(&grid(0, 30, 24), true).unwrap().bunched.unwrap();
        assert_eq!((b.first_bucket, b.last_bucket, b.members), (0, 0, 9));
        // One second more and the run is over a quarter.
        let mut t = Timeline::default();
        for _ in 0..5 {
            t.record(0);
        }
        for _ in 0..4 {
            t.record(26);
        }
        t.record(100);
        assert!(t.view(&grid(0, 30, 24), true).unwrap().bunched.is_none());
    }

    #[test]
    fn counters_are_allocated_at_the_second_member() {
        let mut t = Timeline::default();
        assert!(matches!(t, Timeline::Empty));
        t.record(100);
        assert!(matches!(t, Timeline::One(100)));
        t.record(101);
        assert!(matches!(t, Timeline::Many(_)));
    }

    #[test]
    fn a_group_never_holds_more_keys_than_the_cap() {
        let mut t = Timeline::default();
        for e in 0..(HISTOGRAM_BUCKET_CAP as i64 * 3) {
            t.record(e);
        }
        let Timeline::Many(c) = &t else { panic!() };
        assert!(c.keys.len() <= HISTOGRAM_BUCKET_CAP);
        assert_eq!(c.total, HISTOGRAM_BUCKET_CAP as u64 * 3);
        assert_eq!(c.keys.iter().map(|&(_, n)| n).sum::<u64>(), c.total);
    }

    #[test]
    fn merge_order_does_not_change_the_counts() {
        let epochs_a: Vec<i64> = (0..5000).map(|i| i * 3).collect();
        let epochs_b: Vec<i64> = (0..3000).map(|i| i * 7 + 1).collect();
        let build = |es: &[i64]| {
            let mut t = Timeline::default();
            for &e in es {
                t.record(e);
            }
            t
        };
        let mut ab = build(&epochs_a);
        ab.absorb(build(&epochs_b));
        let mut ba = build(&epochs_b);
        ba.absorb(build(&epochs_a));
        let g = Grid {
            origin: 0,
            bucket_seconds: 1000,
            len: 24,
            collected_seconds: 8,
        };
        let (Timeline::Many(x), Timeline::Many(y)) = (&ab, &ba) else {
            panic!()
        };
        assert_eq!(x.on_grid(&g), y.on_grid(&g));
        assert_eq!(x.total, 8000);
    }

    #[test]
    fn rebinned_counts_equal_direct_placement() {
        // Every epoch placed directly on the grid by its own second must
        // land where the re-binned counts put it, whatever width the group
        // coarsened to, as long as the builder's width is at least that.
        let epochs: Vec<i64> = (0..20_000).map(|i| (i * 37) % 86_400).collect();
        let mut t = Timeline::default();
        for &e in &epochs {
            t.record(e);
        }
        let Timeline::Many(c) = &t else { panic!() };
        let g = Grid {
            origin: 0,
            bucket_seconds: 3601,
            len: 24,
            collected_seconds: c.width.max(32),
        };
        let mut direct = vec![0u64; 24];
        for &e in &epochs {
            let key = e.div_euclid(g.collected_seconds as i64);
            direct[g.index(key)] += 1;
        }
        assert_eq!(c.on_grid(&g), direct);
    }

    #[test]
    fn the_view_needs_three_members_in_two_buckets() {
        let g = grid(0, 60, 24);
        let mut t = Timeline::default();
        t.record(0);
        t.record(120);
        assert!(t.view(&g, true).is_none(), "two members");
        let mut t = Timeline::default();
        for _ in 0..5 {
            t.record(10);
        }
        assert!(t.view(&g, true).is_none(), "one bucket");
        t.record(130);
        let v = t.view(&g, true).unwrap();
        assert_eq!(v.buckets.iter().sum::<u64>(), 6);
        assert_eq!(v.buckets[0], 5);
        assert_eq!(v.buckets[2], 1);
        assert_eq!(v.bucket_seconds, 60);
    }

    // 2026-09-09T09:00:00Z
    const NINE: i64 = 1_788_944_400;

    #[test]
    fn run_times_are_clock_times_on_one_date() {
        let (from, to) = run_times(
            NINE + 7 * 3600,
            NINE + 7 * 3600 + 300,
            NINE,
            NINE + 8 * 3600,
            true,
        );
        assert_eq!((from.as_str(), to.as_str()), ("16:00", "16:05"));
        // Within one minute the seconds are written.
        let (from, to) = run_times(NINE + 3, NINE + 40, NINE, NINE + 3600, true);
        assert_eq!((from.as_str(), to.as_str()), ("09:00:03", "09:00:40"));
    }

    #[test]
    fn run_times_write_the_date_across_midnight_with_the_year_only_when_carried() {
        let (from, to) = run_times(NINE + 7 * 3600, NINE + 86_400, NINE, NINE + 86_400, true);
        assert_eq!(
            (from.as_str(), to.as_str()),
            ("2026-09-09 16:00", "2026-09-10 09:00")
        );
        let (from, _) = run_times(NINE + 7 * 3600, NINE + 86_400, NINE, NINE + 86_400, false);
        assert_eq!(from, "09-09 16:00");
    }

    #[test]
    fn a_run_inside_one_day_of_a_longer_group_names_the_day_once() {
        let (from, to) = run_times(
            NINE + 7 * 3600,
            NINE + 7 * 3600 + 300,
            NINE,
            NINE + 3 * 86_400,
            true,
        );
        assert_eq!((from.as_str(), to.as_str()), ("2026-09-09 16:00", "16:05"));
    }

    #[test]
    fn a_run_whose_members_span_most_of_the_group_is_not_bunched() {
        // Out-of-order input: the grid starts at the log's first line, so
        // members from before it are clamped into bucket 0 alongside the
        // ones that belong there. Nine members in bucket 0 span two days.
        let mut t = Timeline::default();
        for i in 0..9 {
            t.record(NINE - 2 * 86_400 + i * 20_000);
        }
        t.record(NINE + 20 * 3600);
        let g = Grid {
            origin: NINE,
            bucket_seconds: 3600,
            len: 24,
            collected_seconds: 1,
        };
        let v = t.view(&g, true).unwrap();
        assert_eq!(bunched_run(&v.buckets), Some((0, 0, 9)));
        assert!(v.bunched.is_none());
    }

    #[test]
    fn the_run_is_bounded_by_its_own_members_not_by_bucket_edges() {
        // Steady trickle from 09:00, then a burst 16:55-16:58 at 1 s width.
        let mut t = Timeline::default();
        t.record(NINE);
        t.record(NINE + 3 * 3600);
        for i in 0..98 {
            t.record(NINE + 7 * 3600 + 55 * 60 + i * 2);
        }
        let g = Grid {
            origin: NINE,
            bucket_seconds: 1200,
            len: 24,
            collected_seconds: 1,
        };
        let v = t.view(&g, true).unwrap();
        let b = v.bunched.unwrap();
        assert_eq!(
            (b.first_bucket, b.last_bucket, b.members, b.pct),
            (23, 23, 98, 98)
        );
        assert_eq!(b.clause(), "98% in 16:55\u{2013}16:58");
    }
}
