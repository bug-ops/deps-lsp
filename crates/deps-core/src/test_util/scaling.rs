//! Load-independent complexity guard for adversarial-input tests (issue #1824).
//!
//! A test that asserts `elapsed() < Duration::from_secs(N)` fails a correct linear
//! implementation on a loaded runner and passes a slow-but-quadratic one below the bound.
//! [`assert_scaling`] instead times the same operation at two input sizes inside one process
//! and compares the ratio, so uniform machine load cancels out. Small and full runs are
//! interleaved, so a load step between the two sizes lands on both, and a ratio over the limit
//! is measured a second time before the check fails: a real quadratic regression exceeds the
//! limit on every measurement, a transient load spike does not.

use std::fmt;
use std::time::{Duration, Instant};

/// How much larger the full input is than the small one the ratio is taken against.
const SIZE_FACTOR: u32 = 8;
/// Interleaved small/full repetitions per measurement; the minimum of each side is kept.
const SAMPLES: usize = 3;
/// Measurements taken before a ratio over the limit fails the check.
const MEASUREMENTS: usize = 2;
/// A full-size run faster than this is far below what any superlinear regression on an
/// input this large would take, and too short for a stable ratio.
const NOISE_FLOOR: Duration = Duration::from_millis(100);

/// A `full / small` run-time ratio.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct TimeRatio(f64);

impl TimeRatio {
    fn of(small: Duration, full: Duration) -> Self {
        Self(full.as_secs_f64() / small.as_secs_f64().max(f64::EPSILON))
    }
}

impl fmt::Display for TimeRatio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.1}x", self.0)
    }
}

/// The growth rate [`assert_scaling`] expects of the operation under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedGrowth {
    /// Time grows at most proportionally to input size. A quadratic regression grows
    /// `SIZE_FACTOR` times faster than that.
    Linear,
    /// Time grows as `n log n` (a `BTreeMap`-backed structure): the healthy ratio sits above
    /// `SIZE_FACTOR` (about 13 measured for `MatchedSpans`), so the limit is wider than
    /// [`Self::Linear`]'s while a quadratic regression (about 100) still exceeds it.
    Linearithmic,
    /// Time stays roughly flat as the input grows (a bounded scan or a cached lookup).
    Bounded,
}

impl ExpectedGrowth {
    /// The largest accepted ratio: three times the healthy ratio for `Linear`, five times the
    /// size factor for `Linearithmic`, half the size factor for `Bounded`.
    fn max_ratio(self) -> TimeRatio {
        let size_factor = f64::from(SIZE_FACTOR);
        TimeRatio(match self {
            Self::Linear => size_factor * 3.0,
            Self::Linearithmic => size_factor * 5.0,
            Self::Bounded => size_factor / 2.0,
        })
    }
}

/// Which input a timed run uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Size {
    Small,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Verdict {
    Pass,
    BelowFloor,
    Fail {
        small: Duration,
        full: Duration,
        ratio: TimeRatio,
    },
}

/// Decides whether the operation scales as `expected`. `sample(size)` runs and times one
/// repetition at that size; it is injected so the decision logic is testable without a clock.
fn judge(
    expected: ExpectedGrowth,
    noise_floor: Duration,
    mut sample: impl FnMut(Size) -> Duration,
) -> Verdict {
    let mut best: Option<Verdict> = None;
    for _ in 0..MEASUREMENTS {
        let mut small = Duration::MAX;
        let mut full = Duration::MAX;
        for _ in 0..SAMPLES {
            small = small.min(sample(Size::Small));
            full = full.min(sample(Size::Full));
        }
        if full < noise_floor {
            return Verdict::BelowFloor;
        }
        let ratio = TimeRatio::of(small, full);
        if ratio <= expected.max_ratio() {
            return Verdict::Pass;
        }
        let candidate = Verdict::Fail { small, full, ratio };
        best = match best {
            Some(Verdict::Fail { ratio: kept, .. }) if kept <= ratio => best,
            _ => Some(candidate),
        };
    }
    best.expect("MEASUREMENTS is non-zero")
}

/// Asserts that `run` grows as `expected` between a small and the full input, and returns the
/// full-size run's result for the caller's own correctness assertions.
///
/// `prepare(units)` builds the input outside the timed region; it is called with
/// `full_units / 8` and with `full_units`. For a lookup-heavy operation, make the number of
/// lookups proportional to `units` as well: scaling lookups alone cannot expose a per-lookup
/// cost that depends on input size. Parts of the input that do not scale with `units` pull the
/// healthy ratio below 8; the limits still separate a quadratic regression from it.
///
/// # Panics
///
/// Panics when the full-size run takes at least 100 ms and, on both of two interleaved
/// measurements, its time ratio to the small run exceeds the limit for `expected`.
///
/// # Examples
///
/// ```
/// use deps_core::test_util::scaling::{ExpectedGrowth, assert_scaling};
///
/// let sum = assert_scaling(
///     "sum",
///     ExpectedGrowth::Linear,
///     1_000,
///     |units| (0..units as u64).collect::<Vec<_>>(),
///     |input| input.iter().sum::<u64>(),
/// );
/// assert_eq!(sum, 499_500);
/// ```
pub fn assert_scaling<I, R>(
    label: &str,
    expected: ExpectedGrowth,
    full_units: usize,
    prepare: impl Fn(usize) -> I,
    run: impl Fn(&I) -> R,
) -> R {
    let small_input = prepare((full_units / SIZE_FACTOR as usize).max(1));
    let full_input = prepare(full_units);
    let mut result = None;
    let verdict = judge(expected, NOISE_FLOOR, |size| {
        let input = match size {
            Size::Small => &small_input,
            Size::Full => &full_input,
        };
        let start = Instant::now();
        let out = run(input);
        let elapsed = start.elapsed();
        if size == Size::Full {
            result = Some(out);
        }
        elapsed
    });
    if let Verdict::Fail { small, full, ratio } = verdict {
        panic!(
            "{label}: {SIZE_FACTOR}x the input took {ratio} the time ({small:?} -> {full:?}), \
             expected {expected:?} growth (max ratio {})",
            expected.max_ratio()
        );
    }
    result.expect("the full-size input is always sampled")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    /// Scripts the durations `judge` sees, one per `(round, size)`, and records call order.
    fn scripted(
        rounds: &[(u64, u64)],
    ) -> (
        impl FnMut(Size) -> Duration + '_,
        std::rc::Rc<std::cell::RefCell<Vec<Size>>>,
    ) {
        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let log = std::rc::Rc::clone(&calls);
        let sample = move |size: Size| {
            let index = log.borrow().len();
            log.borrow_mut().push(size);
            let round = (index / (2 * SAMPLES)).min(rounds.len() - 1);
            let (small, full) = rounds[round];
            Duration::from_millis(match size {
                Size::Small => small,
                Size::Full => full,
            })
        };
        (sample, calls)
    }

    fn verdict(expected: ExpectedGrowth, rounds: &[(u64, u64)]) -> Verdict {
        judge(expected, Duration::from_millis(1), scripted(rounds).0)
    }

    #[test]
    fn samples_are_interleaved_small_then_full() {
        let (sample, calls) = scripted(&[(10, 80)]);
        judge(ExpectedGrowth::Linear, Duration::from_millis(1), sample);
        let expected: Vec<Size> = (0..SAMPLES)
            .flat_map(|_| [Size::Small, Size::Full])
            .collect();
        assert_eq!(*calls.borrow(), expected);
    }

    #[test]
    fn healthy_ratio_passes_each_growth() {
        assert_eq!(verdict(ExpectedGrowth::Linear, &[(10, 80)]), Verdict::Pass);
        assert_eq!(
            verdict(ExpectedGrowth::Linearithmic, &[(10, 130)]),
            Verdict::Pass
        );
        assert_eq!(verdict(ExpectedGrowth::Bounded, &[(10, 12)]), Verdict::Pass);
    }

    #[test]
    fn a_ratio_over_the_limit_on_every_measurement_fails() {
        let quadratic = [(10, 640)];
        assert_matches!(
            verdict(ExpectedGrowth::Linear, &quadratic),
            Verdict::Fail { .. }
        );
        assert_matches!(
            verdict(ExpectedGrowth::Linearithmic, &[(10, 1000)]),
            Verdict::Fail { .. }
        );
        assert_matches!(
            verdict(ExpectedGrowth::Bounded, &[(10, 80)]),
            Verdict::Fail { .. }
        );
    }

    #[test]
    fn a_transient_spike_is_remeasured_and_passes() {
        assert_eq!(
            verdict(ExpectedGrowth::Linear, &[(10, 400), (10, 80)]),
            Verdict::Pass
        );
    }

    #[test]
    fn the_smaller_failing_ratio_is_reported() {
        let Verdict::Fail { ratio, .. } = verdict(ExpectedGrowth::Linear, &[(10, 900), (10, 640)])
        else {
            panic!("expected a failure");
        };
        assert_eq!(ratio, TimeRatio(64.0));
    }

    #[test]
    fn a_full_run_below_the_noise_floor_is_not_compared() {
        assert_eq!(
            judge(
                ExpectedGrowth::Bounded,
                Duration::from_secs(60),
                scripted(&[(1, 900)]).0
            ),
            Verdict::BelowFloor
        );
    }

    #[test]
    fn assert_scaling_returns_the_full_run_result() {
        let result = assert_scaling(
            "tiny",
            ExpectedGrowth::Linear,
            100,
            |units| units,
            |&units| units * 2,
        );
        assert_eq!(result, 200);
    }
}
