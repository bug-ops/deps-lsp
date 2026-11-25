//! #2156.3: `closed_str_enum!` generates the enum, `ALL`, an exhaustive `to_str` and an exact
//! `parse` from one variant list.

use std::collections::HashSet;

crate::macros::closed_str_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Fruit {
        Apple => "apple",
        BloodOrange => "blood-orange",
        Pear => "pear",
    }
    all: pub(super);
    to_str: pub(super) name_of;
    parse: pub(super) from_name;
}

#[test]
fn closed_str_enum_all_lists_each_variant_once_in_declaration_order() {
    assert_eq!(Fruit::ALL, &[Fruit::Apple, Fruit::BloodOrange, Fruit::Pear]);
}

#[test]
fn closed_str_enum_parse_round_trips_every_variant() {
    for variant in Fruit::ALL {
        assert_eq!(Fruit::from_name(variant.name_of()), Some(*variant));
    }
}

#[test]
fn closed_str_enum_names_are_distinct() {
    let names: HashSet<_> = Fruit::ALL.iter().map(|v| v.name_of()).collect();
    assert_eq!(names.len(), Fruit::ALL.len());
}

#[test]
fn closed_str_enum_parse_is_exact_and_case_sensitive() {
    assert_eq!(Fruit::from_name("Apple"), None);
    assert_eq!(Fruit::from_name("apple "), None);
    assert_eq!(Fruit::from_name(""), None);
    assert_eq!(Fruit::from_name("blood-orange"), Some(Fruit::BloodOrange));
}
