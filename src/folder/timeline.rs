use crate::briefing::{Grid, HISTOGRAM_BUCKET_CAP};
use serde::Serialize;

#[derive(Debug, Default)]
pub(super) enum Timeline {
    #[default]
    Empty,
    One(i64),
    Many(Box<Counts>),
}

#[derive(Debug, Clone)]
pub(super) struct Counts {
    width: u64,
    sorted_keys: Vec<(i64, u64)>,
    min: i64,
    max: i64,
    total: u64,
}

impl Counts {
    fn new(epoch: i64) -> Self {
        Self {
            width: 1,
            sorted_keys: vec![(epoch, 1)],
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
        match self.sorted_keys.last_mut() {
            Some((last, count)) if *last == key => *count += 1,
            Some((last, _)) if *last < key => self.sorted_keys.push((key, 1)),
            _ => match self.sorted_keys.binary_search_by_key(&key, |&(k, _)| k) {
                Ok(at) => self.sorted_keys[at].1 += 1,
                Err(at) => self.sorted_keys.insert(at, (key, 1)),
            },
        }
        self.double_width_until_under_cap();
    }

    fn double_width_until_under_cap(&mut self) {
        while self.sorted_keys.len() > HISTOGRAM_BUCKET_CAP {
            self.double_width();
        }
    }

    fn double_width(&mut self) {
        self.width *= 2;
        let mut out: Vec<(i64, u64)> = Vec::with_capacity(self.sorted_keys.len() / 2 + 1);
        for &(key, count) in &self.sorted_keys {
            let key = key.div_euclid(2);
            match out.last_mut() {
                Some((last, c)) if *last == key => *c += count,
                _ => out.push((key, count)),
            }
        }
        self.sorted_keys = out;
    }

    fn merge(&mut self, mut other: Counts) {
        while self.width < other.width {
            self.double_width();
        }
        while other.width < self.width {
            other.double_width();
        }
        let mut out = Vec::with_capacity(self.sorted_keys.len() + other.sorted_keys.len());
        let (mut a, mut b) = (
            self.sorted_keys.iter().peekable(),
            other.sorted_keys.iter().peekable(),
        );
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
        self.sorted_keys = out;
        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);
        self.total += other.total;
        self.double_width_until_under_cap();
    }

    fn place(&self, grid: &Grid, key: i64) -> usize {
        let collected = grid.collected_seconds.max(1);
        debug_assert!(
            self.width.is_power_of_two() && collected.is_power_of_two(),
            "group width {} and builder width {collected} must both be powers of two, \
             so coarsening a group key to the builder's width is exact",
            self.width
        );
        debug_assert!(
            self.width <= collected,
            "a group's keys are a subset of the log-wide builder's at the same width, so its \
             width {} can never pass the builder's {collected}",
            self.width
        );
        if self.width <= collected {
            let ratio = (collected / self.width) as i64;
            grid.index(key.div_euclid(ratio))
        } else {
            grid.index_at(key * self.width as i64)
        }
    }

    fn on_grid(&self, grid: &Grid) -> Vec<u64> {
        let mut buckets = vec![0u64; grid.len];
        for &(key, count) in &self.sorted_keys {
            buckets[self.place(grid, key)] += count;
        }
        buckets
    }

    fn run_seconds(&self, grid: &Grid, first: usize, last: usize) -> (i64, i64) {
        let width = self.width as i64;
        let mut lo = i64::MAX;
        let mut hi = i64::MIN;
        for &(key, _) in &self.sorted_keys {
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

    pub(super) fn view(&self, grid: &Grid, first_stamp_carries_year: bool) -> Option<TimelineView> {
        let Timeline::Many(counts) = self else {
            return None;
        };
        if counts.total < MIN_VIEW_MEMBERS {
            return None;
        }
        let buckets = counts.on_grid(grid);
        if buckets.iter().filter(|&&c| c > 0).count() < MIN_VIEW_BUCKETS {
            return None;
        }
        let bunched = bunched_run(&buckets).and_then(|(first, last, members)| {
            let (lo, hi) = counts.run_seconds(grid, first, last);
            if !within_a_quarter(hi - lo, counts.max - counts.min) {
                return None;
            }
            let (from, to) = run_times(lo, hi, counts.min, counts.max, first_stamp_carries_year);
            Some(Bunched {
                first_bucket_inclusive: first,
                last_bucket_inclusive: last,
                members,
                pct: whole_percent_rounded_down(members, counts.total),
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

#[derive(Debug, Clone)]
pub(super) struct TimelineView {
    pub bucket_seconds: u64,
    pub buckets: Vec<u64>,
    pub bunched: Option<Bunched>,
}

const MIN_VIEW_MEMBERS: u64 = 3;
const MIN_VIEW_BUCKETS: usize = 2;

fn within_a_quarter(part: i64, whole: i64) -> bool {
    part.saturating_mul(4) <= whole
}

fn reaches_ninety_percent(sum: u64, total: u64) -> bool {
    sum * 10 >= total * 9
}

fn whole_percent_rounded_down(part: u64, whole: u64) -> u64 {
    part * 100 / whole
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Bunched {
    #[serde(rename = "first_bucket")]
    pub first_bucket_inclusive: usize,
    #[serde(rename = "last_bucket")]
    pub last_bucket_inclusive: usize,
    pub members: u64,
    pub pct: u64,
    pub from: String,
    pub to: String,
}

impl Bunched {
    pub(super) fn clause(&self) -> String {
        crate::briefing::bunched_clause(self.pct, &self.from, &self.to)
    }
}

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
            if reaches_ninety_percent(sum, total) {
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
    within_a_quarter((end - start + 1) as i64, span as i64).then_some((start, end, members))
}

fn day(epoch: i64) -> i64 {
    epoch.div_euclid(86_400)
}

fn date_format_for(min: i64, max: i64, stamps_carry_year: bool) -> &'static str {
    if day(min) == day(max) {
        ""
    } else if stamps_carry_year {
        "%Y-%m-%d "
    } else {
        "%m-%d "
    }
}

fn show_time(epoch: i64, with_seconds: bool, date: &str) -> String {
    let fmt = format!("{date}{}", if with_seconds { "%H:%M:%S" } else { "%H:%M" });
    jiff::Timestamp::from_second(epoch)
        .map_or_else(|_| epoch.to_string(), |ts| ts.strftime(&fmt).to_string())
}

fn needs_seconds(from: i64, to: i64, date: &str) -> bool {
    show_time(from, false, date) == show_time(to, false, date)
}

fn run_times(from: i64, to: i64, min: i64, max: i64, stamps_carry_year: bool) -> (String, String) {
    let date = date_format_for(min, max, stamps_carry_year);
    let secs = needs_seconds(from, to, date);
    let date_named_once = if day(from) == day(to) { "" } else { date };
    (
        show_time(from, secs, date),
        show_time(to, secs, date_named_once),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_time_out_of_range_epoch_shows_the_raw_number() {
        assert_eq!(
            show_time(i64::MAX, true, "%Y-%m-%d "),
            "9223372036854775807"
        );
    }

    #[test]
    fn show_time_in_range_epoch_shows_utc_date_and_clock() {
        assert_eq!(
            show_time(1_709_164_800, true, "%Y-%m-%d "),
            "2024-02-29 00:00:00"
        );
    }

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
        assert_eq!(
            bunched_run(&[89, 0, 0, 11]),
            None,
            "89 of 100 in one bucket: the 90% run needs two buckets, and two of a \
             four-bucket span is more than a quarter"
        );
        assert_eq!(
            bunched_run(&[89, 1, 0, 10]),
            None,
            "89 + 1 reaches 90% only over two buckets of a four-bucket span"
        );
    }

    #[test]
    fn a_run_of_exactly_a_quarter_of_the_span_is_bunched() {
        assert_eq!(
            bunched_run(&[1, 0, 0, 0, 0, 0, 5, 5]),
            Some((6, 7, 10)),
            "span 8, run 2: exactly a quarter is bunched"
        );
        assert_eq!(
            bunched_run(&[1, 0, 0, 0, 0, 5, 5]),
            None,
            "span 7, run 2: over a quarter"
        );
    }

    #[test]
    fn three_buckets_are_too_short_a_span_and_four_are_enough() {
        assert_eq!(bunched_run(&[19, 0, 1]), None, "a span of three buckets");
        assert_eq!(
            bunched_run(&[19, 0, 0, 1]),
            Some((0, 0, 19)),
            "a span of four buckets"
        );
        assert_eq!(
            bunched_run(&[0, 0, 19, 0, 1, 0, 0]),
            None,
            "the span is the group's own (three buckets), not the grid's seven"
        );
    }

    #[test]
    fn nine_members_are_too_few_and_ten_are_enough() {
        assert_eq!(bunched_run(&[8, 0, 0, 1]), None);
        assert_eq!(bunched_run(&[9, 0, 0, 1]), Some((0, 0, 9)));
    }

    #[test]
    fn the_bunched_share_is_rounded_down_so_it_never_claims_more_than_the_run_holds() {
        assert_eq!(
            whole_percent_rounded_down(2, 3),
            66,
            "2 of 3 is 66%, not 67%"
        );
        assert_eq!(whole_percent_rounded_down(98, 100), 98);
        assert_eq!(whole_percent_rounded_down(99, 100), 99);
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
        assert_eq!(
            bunched_run(&[95, 0, 0, 5]),
            Some((0, 0, 95)),
            "with 95/5 the 95 bucket wins where it stands first"
        );
        assert_eq!(
            bunched_run(&[5, 0, 0, 95]),
            Some((3, 3, 95)),
            "with 5/95 the 95 bucket wins where it stands last"
        );
    }

    #[test]
    fn of_two_shortest_runs_holding_the_same_the_earlier_wins() {
        let buckets = [1, 5, 90, 5, 0, 0, 0, 0, 0, 0, 0, 3];
        assert_eq!(
            bunched_run(&buckets),
            Some((1, 2, 95)),
            "104 members, 90% is 93.6: buckets 1-2 and 2-3 both hold 95, the earlier wins"
        );
    }

    #[test]
    fn of_two_shortest_runs_the_fuller_wins() {
        let buckets = [1, 4, 90, 6, 0, 0, 0, 0, 0, 0, 0, 3];
        assert_eq!(
            bunched_run(&buckets),
            Some((2, 3, 96)),
            "buckets 1-2 hold 94, buckets 2-3 hold 96: the fuller wins"
        );
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
        assert_eq!(c.sorted_keys, vec![(100, 1), (200, 2)]);
        assert_eq!((c.min, c.max, c.total), (100, 200, 3));
    }

    #[test]
    fn the_width_doubles_only_past_the_cap() {
        let cap = HISTOGRAM_BUCKET_CAP as i64;
        let mut c = counts(&(0..cap).collect::<Vec<_>>());
        assert_eq!((c.width, c.sorted_keys.len()), (1, HISTOGRAM_BUCKET_CAP));
        c.record(cap);
        assert_eq!(
            (c.width, c.sorted_keys.len()),
            (2, HISTOGRAM_BUCKET_CAP / 2 + 1)
        );
    }

    #[test]
    fn merging_adds_counts_on_a_shared_key_and_keeps_the_width() {
        let mut a = counts(&[10, 10, 20]);
        a.merge(counts(&[10, 10, 10, 30]));
        assert_eq!(a.width, 1);
        assert_eq!(a.sorted_keys, vec![(10, 5), (20, 1), (30, 1)]);
        assert_eq!((a.min, a.max, a.total), (10, 30, 7));
    }

    #[test]
    fn a_finer_group_is_placed_where_the_log_wide_builder_placed_the_line() {
        let c = counts(&[127, 127, 130]);
        let g = Grid {
            origin: 0,
            bucket_seconds: 100,
            len: 24,
            collected_seconds: 64,
        };
        assert_eq!(
            c.on_grid(&g)[0],
            2,
            "the builder holds second 127 under key 1 at width 64, which starts at second 64: \
             display bucket 0, not the bucket 127 is in"
        );
        assert_eq!(c.on_grid(&g)[1], 1);
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "can never pass the builder's")
    )]
    fn a_group_coarser_than_the_grid_breaks_the_subset_invariant_and_is_placed_by_its_keys_start_in_release()
     {
        let mut c = counts(&[200, 201]);
        c.double_width();
        c.double_width();
        assert_eq!((c.width, c.sorted_keys.clone()), (4, vec![(50, 2)]));
        assert_eq!(c.on_grid(&grid(0, 100, 24))[2], 2);
    }

    #[test]
    fn run_seconds_are_the_seconds_the_runs_keys_cover() {
        let mut c = counts(&[100, 205, 207, 1000]);
        c.double_width();
        c.double_width();
        assert_eq!(c.sorted_keys, vec![(25, 1), (51, 2), (250, 1)]);
        let g = Grid {
            origin: 0,
            bucket_seconds: 100,
            len: 24,
            collected_seconds: 4,
        };
        assert_eq!(
            c.run_seconds(&g, 2, 2),
            (204, 207),
            "key 51 at width 4 covers seconds 204..=207"
        );
        assert_eq!(
            c.run_seconds(&g, 0, 23),
            (100, 1000),
            "the full range is tightened to the group's earliest and latest member"
        );
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
        let mut t = Timeline::default();
        for _ in 0..5 {
            t.record(0);
        }
        for _ in 0..4 {
            t.record(25);
        }
        t.record(100);
        let b = t
            .view(&grid(0, 30, 24), true)
            .unwrap()
            .bunched
            .expect("nine members over seconds 0..=25, one at 100: 25 x 4 = 100 is a quarter");
        assert_eq!(
            (b.first_bucket_inclusive, b.last_bucket_inclusive, b.members),
            (0, 0, 9)
        );
        let mut t = Timeline::default();
        for _ in 0..5 {
            t.record(0);
        }
        for _ in 0..4 {
            t.record(26);
        }
        t.record(100);
        assert!(
            t.view(&grid(0, 30, 24), true).unwrap().bunched.is_none(),
            "one second more and the run is over a quarter"
        );
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
        assert!(c.sorted_keys.len() <= HISTOGRAM_BUCKET_CAP);
        assert_eq!(c.total, HISTOGRAM_BUCKET_CAP as u64 * 3);
        assert_eq!(c.sorted_keys.iter().map(|&(_, n)| n).sum::<u64>(), c.total);
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
        assert_eq!(
            c.on_grid(&g),
            direct,
            "direct placement by each epoch's own second must equal the re-binned counts \
             whenever the builder's width is at least the group's"
        );
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

    const SEP_9_2026_0900_UTC: i64 = 1_788_944_400;

    #[test]
    fn run_times_are_clock_times_on_one_date() {
        let (from, to) = run_times(
            SEP_9_2026_0900_UTC + 7 * 3600,
            SEP_9_2026_0900_UTC + 7 * 3600 + 300,
            SEP_9_2026_0900_UTC,
            SEP_9_2026_0900_UTC + 8 * 3600,
            true,
        );
        assert_eq!((from.as_str(), to.as_str()), ("16:00", "16:05"));
        let (from, to) = run_times(
            SEP_9_2026_0900_UTC + 3,
            SEP_9_2026_0900_UTC + 40,
            SEP_9_2026_0900_UTC,
            SEP_9_2026_0900_UTC + 3600,
            true,
        );
        assert_eq!(
            (from.as_str(), to.as_str()),
            ("09:00:03", "09:00:40"),
            "within one minute the seconds are written"
        );
    }

    #[test]
    fn run_times_write_the_date_across_midnight_with_the_year_only_when_carried() {
        let (from, to) = run_times(
            SEP_9_2026_0900_UTC + 7 * 3600,
            SEP_9_2026_0900_UTC + 86_400,
            SEP_9_2026_0900_UTC,
            SEP_9_2026_0900_UTC + 86_400,
            true,
        );
        assert_eq!(
            (from.as_str(), to.as_str()),
            ("2026-09-09 16:00", "2026-09-10 09:00")
        );
        let (from, _) = run_times(
            SEP_9_2026_0900_UTC + 7 * 3600,
            SEP_9_2026_0900_UTC + 86_400,
            SEP_9_2026_0900_UTC,
            SEP_9_2026_0900_UTC + 86_400,
            false,
        );
        assert_eq!(from, "09-09 16:00");
    }

    #[test]
    fn a_run_inside_one_day_of_a_longer_group_names_the_day_once() {
        let (from, to) = run_times(
            SEP_9_2026_0900_UTC + 7 * 3600,
            SEP_9_2026_0900_UTC + 7 * 3600 + 300,
            SEP_9_2026_0900_UTC,
            SEP_9_2026_0900_UTC + 3 * 86_400,
            true,
        );
        assert_eq!((from.as_str(), to.as_str()), ("2026-09-09 16:00", "16:05"));
    }

    #[test]
    fn a_run_whose_members_span_most_of_the_group_is_not_bunched() {
        let mut t = Timeline::default();
        for i in 0..9 {
            t.record(SEP_9_2026_0900_UTC - 2 * 86_400 + i * 20_000);
        }
        t.record(SEP_9_2026_0900_UTC + 20 * 3600);
        let g = Grid {
            origin: SEP_9_2026_0900_UTC,
            bucket_seconds: 3600,
            len: 24,
            collected_seconds: 1,
        };
        let v = t.view(&g, true).unwrap();
        assert_eq!(bunched_run(&v.buckets), Some((0, 0, 9)));
        assert!(
            v.bunched.is_none(),
            "out-of-order input: the grid starts at the log's first line, so members from \
             before it are clamped into bucket 0; the nine there span two days"
        );
    }

    #[test]
    fn the_run_is_bounded_by_its_own_members_not_by_bucket_edges() {
        let mut t = Timeline::default();
        t.record(SEP_9_2026_0900_UTC);
        t.record(SEP_9_2026_0900_UTC + 3 * 3600);
        for i in 0..98 {
            t.record(SEP_9_2026_0900_UTC + 7 * 3600 + 55 * 60 + i * 2);
        }
        let g = Grid {
            origin: SEP_9_2026_0900_UTC,
            bucket_seconds: 1200,
            len: 24,
            collected_seconds: 1,
        };
        let v = t.view(&g, true).unwrap();
        let b = v.bunched.unwrap();
        assert_eq!(
            (
                b.first_bucket_inclusive,
                b.last_bucket_inclusive,
                b.members,
                b.pct
            ),
            (23, 23, 98, 98),
            "a steady trickle from 09:00, then a burst 16:55-16:58 at 1 s width"
        );
        assert_eq!(b.clause(), "98% in 16:55\u{2013}16:58");
    }
}
