//! Proc-macro implementation backing `deps_core::redact_debug::RedactingDebug` (issue #1238).
//!
//! Not a direct dependency surface: consumers depend on `deps-core` and use
//! `deps_core::redact_debug::RedactingDebug`, never this crate directly — see that module's
//! doc comment for the derive's contract and an `# Examples` doctest.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

#[derive(Clone, Copy)]
enum FieldRedaction {
    Url,
    Key,
    Raw,
}

/// Derives a `Debug` impl requiring every named field to declare its redaction treatment.
///
/// Every field of the struct it's applied to must carry exactly one of `#[redact(url)]`,
/// `#[redact(key)]`, or `#[raw]` — an unannotated, ambiguous, or conflicting field fails to
/// compile instead of silently rendering a credential-shaped value unredacted (#1238).
///
/// Only structs with named fields are supported; an enum, tuple struct, or unit struct is a
/// compile error naming why. See `deps_core::redact_debug`'s re-exported doc for the field
/// attribute contract and a runnable example.
#[proc_macro_derive(RedactingDebug, attributes(redact, raw))]
pub fn derive_redacting_debug(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            input,
            "RedactingDebug only supports structs with named fields (enums are not supported \
             — see issue #1238's Out of Scope; they need per-variant redaction logic)",
        ));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new_spanned(
            &data.fields,
            "RedactingDebug requires named fields (tuple structs and unit structs are not \
             supported in this version — see issue #1238's Out of Scope)",
        ));
    };
    if fields.named.is_empty() {
        return Err(syn::Error::new_spanned(
            fields,
            "RedactingDebug requires at least one named field — a zero-field struct has \
             nothing to redact; use a hand-written `impl Debug` instead",
        ));
    }

    let mut errors: Vec<syn::Error> = Vec::new();
    let mut field_tokens = Vec::new();

    for field in &fields.named {
        // `Fields::Named` guarantees every field has an identifier.
        let Some(field_ident) = &field.ident else {
            continue;
        };
        match field_redaction_kind(field) {
            Ok(kind) => {
                let name = field_ident.to_string();
                field_tokens.push(match kind {
                    FieldRedaction::Url => quote! {
                        .field(#name, &::deps_core::redact_debug::__redact_url_field(&self.#field_ident))
                    },
                    FieldRedaction::Key => quote! {
                        .field(#name, &::deps_core::redact_debug::__redact_key_field(&self.#field_ident))
                    },
                    FieldRedaction::Raw => quote! {
                        .field(#name, &self.#field_ident)
                    },
                });
            }
            Err(e) => errors.push(e),
        }
    }

    if let Some(combined) = errors.into_iter().reduce(|mut acc, e| {
        acc.combine(e);
        acc
    }) {
        return Err(combined);
    }

    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let name_str = ident.to_string();

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::std::fmt::Debug for #ident #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.debug_struct(#name_str)
                    #(#field_tokens)*
                    .finish()
            }
        }
    })
}

/// Determines the field's exactly-one redaction treatment (FR-005): `#[redact(url)]`,
/// `#[redact(key)]`, or `#[raw]`. Zero or 2+ matching attributes on one field is a compile
/// error naming the field and the conflict.
fn field_redaction_kind(field: &syn::Field) -> syn::Result<FieldRedaction> {
    let mut found: Option<FieldRedaction> = None;

    for attr in &field.attrs {
        if attr.path().is_ident("raw") {
            record_redaction(&mut found, FieldRedaction::Raw, attr)?;
        } else if attr.path().is_ident("redact") {
            let mut kind = None;
            attr.parse_nested_meta(|meta| {
                let this_kind = if meta.path.is_ident("url") {
                    FieldRedaction::Url
                } else if meta.path.is_ident("key") {
                    FieldRedaction::Key
                } else {
                    return Err(meta.error("expected `url` or `key` inside `#[redact(...)]`"));
                };
                // Catches `#[redact(url, key)]` — `parse_nested_meta` invokes this closure
                // once per comma-separated argument, so two arguments in one attribute would
                // otherwise silently let the second overwrite the first instead of erroring.
                if kind.is_some() {
                    return Err(
                        meta.error("`#[redact(...)]` accepts exactly one of `url`/`key`, not both")
                    );
                }
                kind = Some(this_kind);
                Ok(())
            })?;
            let Some(kind) = kind else {
                return Err(syn::Error::new_spanned(
                    attr,
                    "`#[redact(...)]` requires `url` or `key`, e.g. `#[redact(url)]`",
                ));
            };
            record_redaction(&mut found, kind, attr)?;
        }
    }

    found.ok_or_else(|| {
        let field_name = field
            .ident
            .as_ref()
            .map_or_else(|| "<field>".to_string(), ToString::to_string);
        syn::Error::new_spanned(
            field,
            format!(
                "field `{field_name}` must carry exactly one of `#[redact(url)]`, \
                 `#[redact(key)]`, or `#[raw]` (RedactingDebug, #1238)"
            ),
        )
    })
}

/// Records `kind` as `field`'s redaction treatment, failing if one was already recorded —
/// the shared conflict check for both the `#[raw]` and `#[redact(...)]` branches above.
fn record_redaction(
    found: &mut Option<FieldRedaction>,
    kind: FieldRedaction,
    attr: &syn::Attribute,
) -> syn::Result<()> {
    if found.is_some() {
        return Err(syn::Error::new_spanned(
            attr,
            "field carries more than one of `#[redact(url)]`, `#[redact(key)]`, `#[raw]` — \
             exactly one is required",
        ));
    }
    *found = Some(kind);
    Ok(())
}
