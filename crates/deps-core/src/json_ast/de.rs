//! A [`serde::Deserializer`] over a depth-checked `jsonc_parser` AST (#1975).
//!
//! Deserializing straight from the AST skips the intermediate `serde_json::Value` tree: a
//! subtree the target type ignores is never visited, let alone materialized.

use std::collections::HashMap;
use std::fmt;

use jsonc_parser::ast::{Object, ObjectProp, Value};
use serde::de::{self, DeserializeSeed, IntoDeserializer, MapAccess, SeqAccess, Visitor};

/// Failure raised while deserializing from the AST.
#[derive(Debug)]
pub(super) struct AstError(String);

impl fmt::Display for AstError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AstError {}

impl de::Error for AstError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self(msg.to_string())
    }
}

/// Deserializer for one AST value.
///
/// Mirrors `serde_json::from_value` semantics for the shapes the workspace uses: numbers are
/// JSON-only (no hex), the last duplicate object key wins, and map keys are strings. Enums
/// are supported only as unit variants spelled as strings.
pub(super) struct AstDeserializer<'v, 'a>(pub(super) &'v Value<'a>);

impl<'de> de::Deserializer<'de> for AstDeserializer<'_, '_> {
    type Error = AstError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, AstError> {
        match self.0 {
            Value::Object(object) => {
                let mut access = ObjectAccess::new(object);
                let value = visitor.visit_map(&mut access)?;
                access.finish().map(|()| value)
            }
            Value::Array(array) => {
                let mut access = ArrayAccess(array.elements.iter());
                let value = visitor.visit_seq(&mut access)?;
                access.finish().map(|()| value)
            }
            Value::StringLit(lit) => visitor.visit_str(&lit.value),
            Value::NumberLit(lit) => {
                let number: serde_json::Number = lit.value.parse().map_err(|_| {
                    <AstError as de::Error>::custom(format_args!(
                        "invalid JSON number `{}`",
                        lit.value
                    ))
                })?;
                if let Some(unsigned) = number.as_u64() {
                    visitor.visit_u64(unsigned)
                } else if let Some(signed) = number.as_i64() {
                    visitor.visit_i64(signed)
                } else {
                    // ASSUMPTION: a number that is neither u64 nor i64 is a finite float, as
                    // `serde_json::Number` has no other representation without
                    // `arbitrary_precision`.
                    visitor.visit_f64(number.as_f64().unwrap_or(f64::NAN))
                }
            }
            Value::BooleanLit(lit) => visitor.visit_bool(lit.value),
            Value::NullKeyword(_) => visitor.visit_unit(),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, AstError> {
        match self.0 {
            Value::NullKeyword(_) => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, AstError> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, AstError> {
        match self.0 {
            Value::StringLit(lit) => visitor.visit_enum(lit.value.as_ref().into_deserializer()),
            other => Err(de::Error::invalid_type(
                unexpected(other),
                &"a string naming a unit enum variant",
            )),
        }
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, AstError> {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        unit unit_struct seq tuple tuple_struct map struct identifier
    }
}

/// Deserializer for an object key: a string that integer targets parse, like
/// `serde_json::from_value` does for `HashMap<u32, _>`; unparsable keys fall back to the string.
struct KeyDeserializer<'k>(&'k str);

macro_rules! key_integers {
    ($($method:ident => $visit:ident: $ty:ty),+ $(,)?) => { $(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, AstError> {
            match self.0.parse::<$ty>() {
                Ok(number) => visitor.$visit(number),
                Err(_) => visitor.visit_str(self.0),
            }
        }
    )+ };
}

impl<'de> de::Deserializer<'de> for KeyDeserializer<'_> {
    type Error = AstError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, AstError> {
        visitor.visit_str(self.0)
    }

    key_integers! {
        deserialize_i8 => visit_i8: i8,
        deserialize_i16 => visit_i16: i16,
        deserialize_i32 => visit_i32: i32,
        deserialize_i64 => visit_i64: i64,
        deserialize_i128 => visit_i128: i128,
        deserialize_u8 => visit_u8: u8,
        deserialize_u16 => visit_u16: u16,
        deserialize_u32 => visit_u32: u32,
        deserialize_u64 => visit_u64: u64,
        deserialize_u128 => visit_u128: u128,
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, AstError> {
        visitor.visit_some(self)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, AstError> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, AstError> {
        visitor.visit_enum(self.0.into_deserializer())
    }

    serde::forward_to_deserialize_any! {
        bool f32 f64 char str string bytes byte_buf unit unit_struct seq tuple tuple_struct map
        struct identifier ignored_any
    }
}

fn unexpected(value: &Value<'_>) -> de::Unexpected<'static> {
    match value {
        Value::Object(_) => de::Unexpected::Map,
        Value::Array(_) => de::Unexpected::Seq,
        Value::StringLit(_) => de::Unexpected::Other("string"),
        Value::NumberLit(_) => de::Unexpected::Other("number"),
        Value::BooleanLit(lit) => de::Unexpected::Bool(lit.value),
        Value::NullKeyword(_) => de::Unexpected::Unit,
    }
}

struct ArrayAccess<'v, 'a>(std::slice::Iter<'v, Value<'a>>);

impl ArrayAccess<'_, '_> {
    /// Rejects elements the visitor left unread, like `serde_json::from_value` (a tuple fed a
    /// longer array).
    fn finish(&self) -> Result<(), AstError> {
        match self.0.len() {
            0 => Ok(()),
            remaining => Err(de::Error::invalid_length(
                remaining,
                &"fewer elements in array",
            )),
        }
    }
}

impl<'de> SeqAccess<'de> for ArrayAccess<'_, '_> {
    type Error = AstError;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, AstError> {
        self.0
            .next()
            .map(|value| seed.deserialize(AstDeserializer(value)))
            .transpose()
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

/// Yields each object property whose key does not recur later, so the last duplicate wins and
/// derived struct visitors never see a duplicate field.
struct ObjectAccess<'v, 'a> {
    properties: std::slice::Iter<'v, ObjectProp<'a>>,
    last_index: HashMap<&'v str, usize>,
    index: usize,
    pending: Option<&'v Value<'a>>,
}

impl ObjectAccess<'_, '_> {
    /// Rejects properties the visitor left unread, like `serde_json::from_value`.
    fn finish(&self) -> Result<(), AstError> {
        let unread = self.properties.as_slice().len();
        if unread == 0 {
            Ok(())
        } else {
            Err(de::Error::invalid_length(unread, &"fewer elements in map"))
        }
    }
}

impl<'v, 'a> ObjectAccess<'v, 'a> {
    fn new(object: &'v Object<'a>) -> Self {
        let mut last_index = HashMap::with_capacity(object.properties.len());
        for (index, prop) in object.properties.iter().enumerate() {
            last_index.insert(prop.name.as_str(), index);
        }
        Self {
            properties: object.properties.iter(),
            last_index,
            index: 0,
            pending: None,
        }
    }
}

impl<'de> MapAccess<'de> for ObjectAccess<'_, '_> {
    type Error = AstError;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, AstError> {
        for prop in self.properties.by_ref() {
            let index = self.index;
            self.index += 1;
            let key = prop.name.as_str();
            if self.last_index.get(key) == Some(&index) {
                self.pending = Some(&prop.value);
                return seed.deserialize(KeyDeserializer(key)).map(Some);
            }
        }
        Ok(None)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, AstError> {
        let value = self
            .pending
            .take()
            .ok_or_else(|| <AstError as de::Error>::custom("value requested before key"))?;
        seed.deserialize(AstDeserializer(value))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.last_index.len())
    }
}
