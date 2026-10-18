//! Load-independent complexity guard for adversarial-input tests (issue #1824).
//!
//! A test that asserts `elapsed() < Duration::from_secs(N)` fails a correct linear
//! implementation on a loaded runner and passes a slow-but-quadratic one below the bound.
//! [`assert_scaling`] instead times the same operation at two input sizes inside one process
//! and compares the ratio, so uniform machine load cancels out.

use std::time::{Duration, Instant};

/// How much larger the full input is than the small one the ratio is taken against.
const SIZE_FACTOR: u32 = 8;
/// Repetitions per size; the minimum is kept, discarding scheduler-induced outliers.
const SAMPLES: usize = 3;
/// A full-size run faster than this is far below what any superlinear regression on an
/// input this large would take, and too short for a stable ratio.
const NOISE_FLOOR: Duration = Duration::from_millis(100);

/// The growth rate [`assert_scaling`] expects of the operation under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedGrowth {
    /// Time grows at most proportionally to input size (a quadratic regression grows
    /// `SIZE_FACTOR` times faster than that).
    Linear,
    /// Time stays roughly flat as the input grows (a bounded scan or a cached lookup).
    Bounded,
}

impl ExpectedGrowth {
    /// The largest accepted `full / small` time ratio: three times the expected ratio for
    /// `Linear`, half the size factor for `Bounded`.
    fn max_ratio(self) -> f64 {
        let size_factor = f64::from(SIZE_FACTOR);
        match self {
            Self::Linear => size_factor * 3.0,
            Self::Bounded => size_factor / 2.0,
        }
    }
}

fn best_of<I, R>(input: &I, run: &impl Fn(&I) -> R) -> (Duration, R) {
    let mut best: Option<(Duration, R)> = None;
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let result = run(input);
        let elapsed = start.elapsed();
        if best.as_ref().is_none_or(|(fastest, _)| elapsed < *fastest) {
            best = Some((elapsed, result));
        }
    }
    best.expect("SAMPLES is non-zero")
}

/// Asserts that `run` grows as `expected` between a small and the full input, and returns the
/// full-size run's result for the caller's own correctness assertions.
///
/// `prepare(units)` builds the input outside the timed region; it is called with
/// `full_units / 8` and with `full_units`. For a lookup-heavy operation, make the number of
/// lookups proportional to `units` as well: scaling lookups alone cannot expose a per-lookup
/// cost that depends on input size.
///
/// # Panics
///
/// Panics when the full-size run takes at least 100 ms and its time ratio to the small run
/// exceeds the limit for `expected`.
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
    assert_scaling_above(label, expected, NOISE_FLOOR, full_units, prepare, run)
}

fn assert_scaling_above<I, R>(
    label: &str,
    expected: ExpectedGrowth,
    noise_floor: Duration,
    full_units: usize,
    prepare: impl Fn(usize) -> I,
    run: impl Fn(&I) -> R,
) -> R {
    let small_input = prepare((full_units / SIZE_FACTOR as usize).max(1));
    let full_input = prepare(full_units);
    let (small, _) = best_of(&small_input, &run);
    let (full, result) = best_of(&full_input, &run);
    if full >= noise_floor {
        let ratio = full.as_secs_f64() / small.as_secs_f64().max(f64::EPSILON);
        assert!(
            ratio <= expected.max_ratio(),
            "{label}: {SIZE_FACTOR}x the input took {ratio:.1}x the time ({small:?} -> {full:?}), \
             expected {expected:?} growth (max ratio {:.1})",
            expected.max_ratio()
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spin(units: usize) -> u64 {
        (0..units as u64).fold(0, |acc, i| std::hint::black_box(acc ^ i))
    }

    const FLOOR: Duration = Duration::ZERO;

    #[test]
    fn linear_work_passes_linear_expectation() {
        let result = assert_scaling_above(
            "linear",
            ExpectedGrowth::Linear,
            FLOOR,
            8_000_000,
            |units| units,
            |&units| spin(units),
        );
        assert_eq!(result, spin(8_000_000));
    }

    #[test]
    #[should_panic(expected = "expected Linear growth")]
    fn quadratic_work_fails_linear_expectation() {
        assert_scaling_above(
            "quadratic",
            ExpectedGrowth::Linear,
            FLOOR,
            8_000,
            |units| units,
            |&units| (0..units).map(|_| spin(units)).sum::<u64>(),
        );
    }

    #[test]
    fn flat_work_passes_bounded_expectation() {
        assert_scaling_above(
            "flat",
            ExpectedGrowth::Bounded,
            FLOOR,
            8_000_000,
            |units| units,
            |_| spin(2_000_000),
        );
    }

    #[test]
    #[should_panic(expected = "expected Bounded growth")]
    fn linear_work_fails_bounded_expectation() {
        assert_scaling_above(
            "linear-as-bounded",
            ExpectedGrowth::Bounded,
            FLOOR,
            8_000_000,
            |units| units,
            |&units| spin(units),
        );
    }

    #[test]
    fn work_below_noise_floor_is_not_compared() {
        assert_scaling_above(
            "tiny",
            ExpectedGrowth::Bounded,
            Duration::from_secs(60),
            8_000,
            |units| units,
            |&units| spin(units),
        );
    }
}
