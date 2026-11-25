//! Non-cryptographic hashing shared across the workspace.

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64-bit hash of `bytes`.
///
/// Detects accidental corruption and derives stable file and branch names; it is not
/// collision-resistant against an adversary. The output is persisted (cache entry names, update
/// branch names), so it must never change.
///
/// # Examples
///
/// ```
/// use deps_core::hash::fnv1a64;
///
/// assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
/// assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
/// ```
#[must_use]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(FNV_OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME)
    })
}
