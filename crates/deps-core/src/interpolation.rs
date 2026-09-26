//! Bounded property/variable values for manifest interpolation (issue #1481).
//!
//! Maven's `${property}` and Gradle's `version.ref`/`$name`/`${name}` substitutions each
//! resolve through a `HashMap` keyed by property name. Without a per-value bound, a manifest
//! declaring up to [`deps_core::MAX_DEPENDENCIES_PER_DOCUMENT`](crate::MAX_DEPENDENCIES_PER_DOCUMENT)
//! kept dependencies, each resolving an unbounded property value, retains
//! `kept_deps * value_len` bytes with no cap on the second factor (CWE-400). [`PropertyValue`]
//! makes an oversized value unrepresentable in the map that feeds resolution, so every
//! reference to it falls through the existing "unresolved" path instead of retaining the raw
//! text.

/// Maximum byte length of a single interpolated property/variable value.
///
/// Real version strings and version ranges are well under 100 bytes; 1 KiB leaves headroom
/// for `systemPath`-style path values while still bounding worst-case retained memory to
/// `MAX_DEPENDENCIES_PER_DOCUMENT * MAX_INTERPOLATED_VALUE_BYTES` per resolution pass.
pub const MAX_INTERPOLATED_VALUE_BYTES: usize = 1024;

/// A property/variable value that has been checked against
/// [`MAX_INTERPOLATED_VALUE_BYTES`] and is guaranteed not to exceed it.
///
/// This is the type-level gate for issue #1481: `HashMap<String, PropertyValue>` (rather than
/// `HashMap<String, String>`) as the map type that feeds Maven's `${property}` and Gradle's
/// `version.ref`/`$name`/`${name}` resolution makes an oversized retained value
/// unrepresentable, instead of relying on a runtime check at every call site.
///
/// # Examples
///
/// ```
/// use deps_core::interpolation::{MAX_INTERPOLATED_VALUE_BYTES, PropertyValue};
///
/// let value = PropertyValue::new("1.2.3".to_string()).unwrap();
/// assert_eq!(value.as_str(), "1.2.3");
///
/// let oversized = "x".repeat(MAX_INTERPOLATED_VALUE_BYTES + 1);
/// assert!(PropertyValue::new(oversized).is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PropertyValue(String);

impl PropertyValue {
    /// Wraps `value` as a `PropertyValue`, rejecting it if longer than
    /// [`MAX_INTERPOLATED_VALUE_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`OversizedPropertyValue`] if `value.len()` exceeds
    /// [`MAX_INTERPOLATED_VALUE_BYTES`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::interpolation::PropertyValue;
    ///
    /// assert!(PropertyValue::new("2.0.16".to_string()).is_ok());
    /// ```
    pub fn new(value: String) -> Result<Self, OversizedPropertyValue> {
        if value.len() > MAX_INTERPOLATED_VALUE_BYTES {
            return Err(OversizedPropertyValue { len: value.len() });
        }
        Ok(Self(value))
    }

    /// Returns the property value as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::interpolation::PropertyValue;
    ///
    /// let value = PropertyValue::new("3.2.0".to_string()).unwrap();
    /// assert_eq!(value.as_str(), "3.2.0");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the byte length of the property value.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::interpolation::PropertyValue;
    ///
    /// let value = PropertyValue::new("3.2.0".to_string()).unwrap();
    /// assert_eq!(value.len(), 5);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the property value is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::interpolation::PropertyValue;
    ///
    /// let value = PropertyValue::new(String::new()).unwrap();
    /// assert!(value.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Inserts `value` into `map` under `key`, dropping it instead if it exceeds
/// [`MAX_INTERPOLATED_VALUE_BYTES`] (#1481) rather than retaining an unbounded value.
///
/// Every ecosystem's own bounded-property map (`deps-maven`'s `properties`, `deps-gradle`'s
/// `version_refs` and `gradle.properties` map) shares this same insert-time gate instead of
/// each reimplementing the check-log-drop pattern independently. Logs at `debug` with the
/// value's length and `context` only — never the value's content — so a caller can tell
/// which map dropped a value without leaking a potentially large or sensitive payload into
/// tracing output. A dropped value falls through to whatever "unresolved" behavior the
/// caller's own lookup path already has for a missing key.
///
/// # Examples
///
/// ```
/// use deps_core::interpolation::{MAX_INTERPOLATED_VALUE_BYTES, insert_bounded};
/// use std::collections::HashMap;
///
/// let mut map = HashMap::new();
/// insert_bounded(&mut map, "ver".to_string(), "1.2.3".to_string(), "example");
/// assert_eq!(map.get("ver").map(|v| v.as_str()), Some("1.2.3"));
///
/// insert_bounded(
///     &mut map,
///     "big".to_string(),
///     "x".repeat(MAX_INTERPOLATED_VALUE_BYTES + 1),
///     "example",
/// );
/// assert!(!map.contains_key("big"));
/// ```
pub fn insert_bounded(
    map: &mut std::collections::HashMap<String, PropertyValue>,
    key: String,
    value: String,
    context: &str,
) {
    match PropertyValue::new(value) {
        Ok(value) => {
            map.insert(key, value);
        }
        Err(err) => {
            tracing::debug!(
                context,
                len = err.len,
                "property value exceeds cap; dropping"
            );
        }
    }
}

/// A property/variable value exceeded [`MAX_INTERPOLATED_VALUE_BYTES`] and was rejected by
/// [`PropertyValue::new`].
///
/// # Examples
///
/// ```
/// use deps_core::interpolation::{MAX_INTERPOLATED_VALUE_BYTES, PropertyValue};
///
/// let err = PropertyValue::new("x".repeat(MAX_INTERPOLATED_VALUE_BYTES + 1)).unwrap_err();
/// assert_eq!(err.len, MAX_INTERPOLATED_VALUE_BYTES + 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("property value length {len} exceeds cap of {MAX_INTERPOLATED_VALUE_BYTES} bytes")]
pub struct OversizedPropertyValue {
    /// The rejected value's byte length.
    pub len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_value_at_exact_cap() {
        let value = "x".repeat(MAX_INTERPOLATED_VALUE_BYTES);
        assert!(PropertyValue::new(value).is_ok());
    }

    #[test]
    fn rejects_value_one_byte_over_cap() {
        let value = "x".repeat(MAX_INTERPOLATED_VALUE_BYTES + 1);
        let err = PropertyValue::new(value).unwrap_err();
        assert_eq!(err.len, MAX_INTERPOLATED_VALUE_BYTES + 1);
    }
}
