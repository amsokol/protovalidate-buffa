//! Emit validation code for `repeated` and `map` fields, including per-element
//! / per-key / per-value rule application and message-type recursion.

use anyhow::Result;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::scan::{FieldKind, MapStandard, RepeatedStandard};

pub(crate) fn kind_variant_to_subscript(kind_variant: &str) -> Option<TokenStream> {
    match kind_variant {
        "Bool" => Some(quote! { ::protovalidate_buffa::Subscript::BoolKey(*key) }),
        "Int32" | "Sint32" | "Sfixed32" => {
            Some(quote! { ::protovalidate_buffa::Subscript::IntKey(i64::from(*key)) })
        }
        "Int64" | "Sint64" | "Sfixed64" => {
            Some(quote! { ::protovalidate_buffa::Subscript::IntKey(*key) })
        }
        "Uint32" | "Fixed32" => {
            Some(quote! { ::protovalidate_buffa::Subscript::UintKey(u64::from(*key)) })
        }
        "Uint64" | "Fixed64" => Some(quote! { ::protovalidate_buffa::Subscript::UintKey(*key) }),
        "String" => Some(quote! {
            ::protovalidate_buffa::Subscript::StringKey(::std::borrow::Cow::Owned(
                ::core::convert::AsRef::<str>::as_ref(key).to_owned()
            ))
        }),
        _ => None,
    }
}

fn repeated_field_path(name: &str, number: i32, ty: &str) -> TokenStream {
    let ty_ident = format_ident!("{}", ty);
    quote! {
        ::protovalidate_buffa::FieldPath {
            elements: ::std::vec![
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#number),
                    field_name: Some(::std::borrow::Cow::Borrowed(#name)),
                    field_type: Some(::protovalidate_buffa::FieldType::#ty_ident),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
            ],
        }
    }
}

fn repeated_rule_path(inner: &str, inner_num: i32) -> TokenStream {
    repeated_rule_path_ty(inner, inner_num, "Uint64")
}

fn repeated_rule_path_ty(inner: &str, inner_num: i32, ty: &str) -> TokenStream {
    let ty_ident = format_ident!("{}", ty);
    quote! {
        ::protovalidate_buffa::FieldPath {
            elements: ::std::vec![
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(18i32),
                    field_name: Some(::std::borrow::Cow::Borrowed("repeated")),
                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#inner_num),
                    field_name: Some(::std::borrow::Cow::Borrowed(#inner)),
                    field_type: Some(::protovalidate_buffa::FieldType::#ty_ident),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
            ],
        }
    }
}

fn map_field_path(name: &str, number: i32) -> TokenStream {
    quote! {
        ::protovalidate_buffa::FieldPath {
            elements: ::std::vec![
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#number),
                    field_name: Some(::std::borrow::Cow::Borrowed(#name)),
                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
            ],
        }
    }
}

fn map_rule_path(inner: &str, inner_num: i32) -> TokenStream {
    map_rule_path_ty(inner, inner_num, "Uint64")
}

fn map_rule_path_ty(inner: &str, inner_num: i32, ty: &str) -> TokenStream {
    let ty_ident = format_ident!("{}", ty);
    quote! {
        ::protovalidate_buffa::FieldPath {
            elements: ::std::vec![
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(19i32),
                    field_name: Some(::std::borrow::Cow::Borrowed("map")),
                    field_type: Some(::protovalidate_buffa::FieldType::Message),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
                ::protovalidate_buffa::FieldPathElement {
                    field_number: Some(#inner_num),
                    field_name: Some(::std::borrow::Cow::Borrowed(#inner)),
                    field_type: Some(::protovalidate_buffa::FieldType::#ty_ident),
                    key_type: None,
                    value_type: None,
                    subscript: None,
                },
            ],
        }
    }
}

// ─── repeated ────────────────────────────────────────────────────────────────

/// Emit the validation snippet for a `repeated` field.
///
/// Handles:
/// - `min_items` / `max_items` length checks.
/// - Per-element scalar rules from `items` (for string/bytes/numeric elements).
/// - Per-element message recursion (for message-typed elements).
///
/// # Errors
///
/// Returns an error if the emitted `TokenStream` cannot be assembled (currently
/// infallible; reserved for future element-level emitters that may fail).
///
/// # Panics
///
/// Panics if `min_items` or `max_items` cannot be converted to `usize`. In
/// practice proto length bounds are small non-negative integers, so this
/// invariant always holds.
pub fn emit_repeated(
    accessor: &syn::Ident,
    name_lit: &str,
    field_number: i32,
    element_type_variant: &str,
    spec: &RepeatedStandard,
    element_kind: &FieldKind,
    schemas: &crate::emit::cel::SchemaIndex,
) -> Result<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let fp = || repeated_field_path(name_lit, field_number, element_type_variant);

    if let Some(min) = spec.min_items {
        let min_usize = usize::try_from(min).expect("proto length bound fits in usize");
        let field = fp();
        let rule = repeated_rule_path("min_items", 1);
        out.push(quote! {
            if self.#accessor.len() < #min_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("repeated.min_items"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "list must contain at least {} items (got {})",
                        #min_usize, self.#accessor.len()
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(max) = spec.max_items {
        let max_usize = usize::try_from(max).expect("proto length bound fits in usize");
        let field = fp();
        let rule = repeated_rule_path("max_items", 2);
        out.push(quote! {
            if self.#accessor.len() > #max_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("repeated.max_items"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "list must contain at most {} items (got {})",
                        #max_usize, self.#accessor.len()
                    )),
                    for_key: false,
                });
            }
        });
    }

    if spec.unique == Some(true) && !matches!(element_kind, FieldKind::Message { .. }) {
        let field = fp();
        let rule = repeated_rule_path_ty("unique", 3, "Bool");
        out.push(quote! {
            {
                let mut seen = ::std::collections::HashSet::with_capacity(self.#accessor.len());
                let dup = self.#accessor.iter().any(|item| !seen.insert(item));
                if dup {
                    violations.push(::protovalidate_buffa::Violation {
                        field: #field, rule: #rule,
                        rule_id: ::std::borrow::Cow::Borrowed("repeated.unique"),
                        message: ::std::borrow::Cow::Borrowed("repeated value must contain unique items"),
                        for_key: false,
                    });
                }
            }
        });
    }

    // Per-element scalar rules — only for non-message elements.
    // Message elements are handled by the recursion block below.
    if let Some(items) = &spec.items {
        if matches!(items.ignore, crate::scan::Ignore::Always) {
            // Entirely skip per-element checks.
            return Ok(quote! { #( #out )* });
        }
        let elem_ident = format_ident!("elem");
        let site = crate::emit::field::RuleSite::repeated_item(
            name_lit,
            field_number,
            element_type_variant,
        );
        let checks = crate::emit::field::emit_scalar_rules(
            &element_value(element_kind, &elem_ident),
            element_kind,
            &items.standard,
            &site,
        )?;
        if !checks.is_empty() {
            // IGNORE_IF_ZERO_VALUE on items: skip zero-value elements.
            let guard = if matches!(items.ignore, crate::scan::Ignore::IfZeroValue) {
                zero_guard(element_kind, &elem_ident)
            } else {
                None
            };
            let body = guard.map_or_else(
                || quote! { #( #checks )* },
                |g| quote! { if #g { #( #checks )* } },
            );
            out.push(quote! {
                for (idx, elem) in self.#accessor.iter().enumerate() {
                    #body
                }
            });
        }
    }

    // Per-element WKT (Any, Duration) rules.
    if let Some(items) = &spec.items
        && !matches!(items.ignore, crate::scan::Ignore::Always)
        && let FieldKind::Message { full_name } = element_kind
    {
        if full_name == "google.protobuf.Duration"
            && let Some(d) = &items.standard.duration
        {
            let fnum = field_number;
            let nl = name_lit;
            let emit_dur = |out: &mut Vec<TokenStream>,
                            inner_name: &str,
                            inner_num: i32,
                            bound: &(i64, i32),
                            op: &str,
                            rule_id: &str,
                            msg: &str| {
                let (secs, nano) = *bound;
                let cond: TokenStream = match op {
                    "gte" => {
                        quote! { elem_ns < #secs as i128 * 1_000_000_000 + #nano as i128 }
                    }
                    "gt" => {
                        quote! { elem_ns <= #secs as i128 * 1_000_000_000 + #nano as i128 }
                    }
                    "lte" => {
                        quote! { elem_ns > #secs as i128 * 1_000_000_000 + #nano as i128 }
                    }
                    "lt" => {
                        quote! { elem_ns >= #secs as i128 * 1_000_000_000 + #nano as i128 }
                    }
                    _ => return,
                };
                let inner_name_s = inner_name.to_string();
                let rid = rule_id.to_string();
                let ms = msg.to_string();
                out.push(quote! {
                    for (idx, elem) in self.#accessor.iter().enumerate() {
                        let elem_ns: i128 = elem.seconds as i128 * 1_000_000_000 + elem.nanos as i128;
                        if #cond {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::FieldPath {
                                    elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                                        field_number: Some(#fnum),
                                        field_name: Some(::std::borrow::Cow::Borrowed(#nl)),
                                        field_type: Some(::protovalidate_buffa::FieldType::Message),
                                        key_type: None, value_type: None,
                                        subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                                    }],
                                },
                                rule: ::protovalidate_buffa::FieldPath {
                                    elements: ::std::vec![
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(18i32), field_name: Some(::std::borrow::Cow::Borrowed("repeated")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(4i32), field_name: Some(::std::borrow::Cow::Borrowed("items")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(21i32), field_name: Some(::std::borrow::Cow::Borrowed("duration")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(#inner_num), field_name: Some(::std::borrow::Cow::Borrowed(#inner_name_s)), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                    ],
                                },
                                rule_id: ::std::borrow::Cow::Borrowed(#rid),
                                message: ::std::borrow::Cow::Borrowed(#ms),
                                for_key: false,
                            });
                        }
                    }
                });
            };
            if let Some(b) = &d.gte {
                emit_dur(
                    &mut out,
                    "gte",
                    6,
                    b,
                    "gte",
                    "duration.gte",
                    "must be greater than or equal to 0.001s",
                );
            }
            if let Some(b) = &d.gt {
                emit_dur(&mut out, "gt", 5, b, "gt", "duration.gt", "");
            }
            if let Some(b) = &d.lte {
                emit_dur(&mut out, "lte", 4, b, "lte", "duration.lte", "");
            }
            if let Some(b) = &d.lt {
                emit_dur(&mut out, "lt", 3, b, "lt", "duration.lt", "");
            }
        }
        if full_name == "google.protobuf.Timestamp"
            && let Some(t) = &items.standard.timestamp
        {
            let fnum = field_number;
            let nl = name_lit;
            let emit_ts = |out: &mut Vec<TokenStream>,
                           inner_name: &str,
                           inner_num: i32,
                           bound: &(i64, i32),
                           op: &str,
                           rule_id: &str| {
                let (secs, nano) = *bound;
                let cond: TokenStream = match op {
                    "gte" => {
                        quote! { elem_ns < #secs as i128 * 1_000_000_000 + #nano as i128 }
                    }
                    "gt" => {
                        quote! { elem_ns <= #secs as i128 * 1_000_000_000 + #nano as i128 }
                    }
                    "lte" => {
                        quote! { elem_ns > #secs as i128 * 1_000_000_000 + #nano as i128 }
                    }
                    "lt" => {
                        quote! { elem_ns >= #secs as i128 * 1_000_000_000 + #nano as i128 }
                    }
                    _ => return,
                };
                let inner_name_s = inner_name.to_string();
                let rid = rule_id.to_string();
                out.push(quote! {
                    for (idx, elem) in self.#accessor.iter().enumerate() {
                        let elem_ns: i128 = elem.seconds as i128 * 1_000_000_000 + elem.nanos as i128;
                        if #cond {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::FieldPath {
                                    elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                                        field_number: Some(#fnum),
                                        field_name: Some(::std::borrow::Cow::Borrowed(#nl)),
                                        field_type: Some(::protovalidate_buffa::FieldType::Message),
                                        key_type: None, value_type: None,
                                        subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                                    }],
                                },
                                rule: ::protovalidate_buffa::FieldPath {
                                    elements: ::std::vec![
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(18i32), field_name: Some(::std::borrow::Cow::Borrowed("repeated")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(4i32), field_name: Some(::std::borrow::Cow::Borrowed("items")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(22i32), field_name: Some(::std::borrow::Cow::Borrowed("timestamp")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(#inner_num), field_name: Some(::std::borrow::Cow::Borrowed(#inner_name_s)), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                    ],
                                },
                                rule_id: ::std::borrow::Cow::Borrowed(#rid),
                                message: ::std::borrow::Cow::Borrowed(""),
                                for_key: false,
                            });
                        }
                    }
                });
            };
            if let Some(b) = &t.gte {
                emit_ts(&mut out, "gte", 6, b, "gte", "timestamp.gte");
            }
            if let Some(b) = &t.gt {
                emit_ts(&mut out, "gt", 5, b, "gt", "timestamp.gt");
            }
            if let Some(b) = &t.lte {
                emit_ts(&mut out, "lte", 4, b, "lte", "timestamp.lte");
            }
            if let Some(b) = &t.lt {
                emit_ts(&mut out, "lt", 3, b, "lt", "timestamp.lt");
            }
        }
        if full_name == "google.protobuf.Any"
            && let Some(a) = &items.standard.any_rules
        {
            if !a.in_set.is_empty() {
                let set = &a.in_set;
                let fnum = field_number;
                let nl = name_lit;
                out.push(quote! {
                    for (idx, elem) in self.#accessor.iter().enumerate() {
                        const ALLOWED: &[&str] = &[ #( #set ),* ];
                        if !ALLOWED.iter().any(|s| *s == ::core::convert::AsRef::<str>::as_ref(&elem.type_url)) {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::FieldPath {
                                    elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                                        field_number: Some(#fnum),
                                        field_name: Some(::std::borrow::Cow::Borrowed(#nl)),
                                        field_type: Some(::protovalidate_buffa::FieldType::Message),
                                        key_type: None, value_type: None,
                                        subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                                    }],
                                },
                                rule: ::protovalidate_buffa::FieldPath {
                                    elements: ::std::vec![
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(18i32), field_name: Some(::std::borrow::Cow::Borrowed("repeated")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(4i32), field_name: Some(::std::borrow::Cow::Borrowed("items")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(20i32), field_name: Some(::std::borrow::Cow::Borrowed("any")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(2i32), field_name: Some(::std::borrow::Cow::Borrowed("in")), field_type: Some(::protovalidate_buffa::FieldType::String), key_type: None, value_type: None, subscript: None },
                                    ],
                                },
                                rule_id: ::std::borrow::Cow::Borrowed("any.in"),
                                message: ::std::borrow::Cow::Borrowed("type URL must be in the allow list"),
                                for_key: false,
                            });
                        }
                    }
                });
            }
            if !a.not_in.is_empty() {
                let set = &a.not_in;
                let fnum = field_number;
                let nl = name_lit;
                out.push(quote! {
                    for (idx, elem) in self.#accessor.iter().enumerate() {
                        const DENIED: &[&str] = &[ #( #set ),* ];
                        if DENIED.iter().any(|s| *s == ::core::convert::AsRef::<str>::as_ref(&elem.type_url)) {
                            violations.push(::protovalidate_buffa::Violation {
                                field: ::protovalidate_buffa::FieldPath {
                                    elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                                        field_number: Some(#fnum),
                                        field_name: Some(::std::borrow::Cow::Borrowed(#nl)),
                                        field_type: Some(::protovalidate_buffa::FieldType::Message),
                                        key_type: None, value_type: None,
                                        subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                                    }],
                                },
                                rule: ::protovalidate_buffa::FieldPath {
                                    elements: ::std::vec![
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(18i32), field_name: Some(::std::borrow::Cow::Borrowed("repeated")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(4i32), field_name: Some(::std::borrow::Cow::Borrowed("items")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(20i32), field_name: Some(::std::borrow::Cow::Borrowed("any")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                                        ::protovalidate_buffa::FieldPathElement { field_number: Some(3i32), field_name: Some(::std::borrow::Cow::Borrowed("not_in")), field_type: Some(::protovalidate_buffa::FieldType::String), key_type: None, value_type: None, subscript: None },
                                    ],
                                },
                                rule_id: ::std::borrow::Cow::Borrowed("any.not_in"),
                                message: ::std::borrow::Cow::Borrowed("type URL must not be in the block list"),
                                for_key: false,
                            });
                        }
                    }
                });
            }
        }
    }

    // Per-element predefined (extension-based) rules (`repeated.items.<family>.<ext>`).
    if let Some(items) = &spec.items
        && !matches!(items.ignore, crate::scan::Ignore::Always)
        && !items.standard.predefined.is_empty()
    {
        let element_ty_ident = format_ident!("{}", element_type_variant);
        let family = crate::emit::cel::predef_family_for(element_kind);
        for rule in &items.standard.predefined {
            let id = rule.id.as_str();
            let msg = rule.message.as_str();
            let expr = rule.expression.as_str();
            let ext_num = rule.ext_number;
            let ext_name = &rule.ext_name;
            let ext_ty_ident = format_ident!("{}", rule.ext_field_type);
            let Some(fam) = family else { continue };
            let fam_name = fam.name;
            let fam_num = fam.number;
            let ext_bracketed = format!("[{ext_name}]");
            // Native path: bind `this` to the element value and `rule` to
            // the extension's constant value.
            let fp_quote = quote! {
                ::protovalidate_buffa::FieldPath {
                    elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                        field_number: Some(#field_number),
                        field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                        field_type: Some(::protovalidate_buffa::FieldType::#element_ty_ident),
                        key_type: None, value_type: None,
                        subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                    }],
                }
            };
            let rp_quote = quote! {
                ::protovalidate_buffa::FieldPath {
                    elements: ::std::vec![
                        ::protovalidate_buffa::FieldPathElement { field_number: Some(18i32), field_name: Some(::std::borrow::Cow::Borrowed("repeated")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                        ::protovalidate_buffa::FieldPathElement { field_number: Some(4i32), field_name: Some(::std::borrow::Cow::Borrowed("items")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                        ::protovalidate_buffa::FieldPathElement { field_number: Some(#fam_num), field_name: Some(::std::borrow::Cow::Borrowed(#fam_name)), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                        ::protovalidate_buffa::FieldPathElement { field_number: Some(#ext_num), field_name: Some(::std::borrow::Cow::Borrowed(#ext_bracketed)), field_type: Some(::protovalidate_buffa::FieldType::#ext_ty_ident), key_type: None, value_type: None, subscript: None },
                    ],
                }
            };
            // Element access expression for scalar element kinds. Wrapper
            // elements yield `(*elem).value` which still satisfies CelScalar.
            let elem_access: Option<TokenStream> = match element_kind {
                FieldKind::String => Some(quote! { ::core::convert::AsRef::<str>::as_ref(elem) }),
                FieldKind::Bytes => Some(quote! { ::core::convert::AsRef::<[u8]>::as_ref(elem) }),
                FieldKind::Bool => Some(quote! { (*elem) }),
                FieldKind::Float
                | FieldKind::Double
                | FieldKind::Int32
                | FieldKind::Int64
                | FieldKind::Sint32
                | FieldKind::Sint64
                | FieldKind::Sfixed32
                | FieldKind::Sfixed64
                | FieldKind::Uint32
                | FieldKind::Uint64
                | FieldKind::Fixed32
                | FieldKind::Fixed64
                | FieldKind::Enum { .. } => Some(quote! { (*elem) }),
                FieldKind::Message { full_name } if full_name == "google.protobuf.StringValue" => {
                    Some(quote! { ::core::convert::AsRef::<str>::as_ref(&elem.value) })
                }
                FieldKind::Message { full_name } if full_name == "google.protobuf.BytesValue" => {
                    Some(quote! { ::core::convert::AsRef::<[u8]>::as_ref(&elem.value) })
                }
                FieldKind::Message { full_name }
                    if full_name.starts_with("google.protobuf.")
                        && full_name.ends_with("Value") =>
                {
                    Some(quote! { elem.value })
                }
                _ => None,
            };
            let native = elem_access.and_then(|access| {
                let scalar_kind = match element_kind {
                    FieldKind::Message { full_name }
                        if full_name == "google.protobuf.FloatValue" =>
                    {
                        FieldKind::Float
                    }
                    FieldKind::Message { full_name }
                        if full_name == "google.protobuf.DoubleValue" =>
                    {
                        FieldKind::Double
                    }
                    FieldKind::Message { full_name }
                        if full_name == "google.protobuf.Int32Value" =>
                    {
                        FieldKind::Int32
                    }
                    FieldKind::Message { full_name }
                        if full_name == "google.protobuf.Int64Value" =>
                    {
                        FieldKind::Int64
                    }
                    FieldKind::Message { full_name }
                        if full_name == "google.protobuf.UInt32Value" =>
                    {
                        FieldKind::Uint32
                    }
                    FieldKind::Message { full_name }
                        if full_name == "google.protobuf.UInt64Value" =>
                    {
                        FieldKind::Uint64
                    }
                    FieldKind::Message { full_name }
                        if full_name == "google.protobuf.BoolValue" =>
                    {
                        FieldKind::Bool
                    }
                    FieldKind::Message { full_name }
                        if full_name == "google.protobuf.StringValue" =>
                    {
                        FieldKind::String
                    }
                    FieldKind::Message { full_name }
                        if full_name == "google.protobuf.BytesValue" =>
                    {
                        FieldKind::Bytes
                    }
                    other => match other {
                        FieldKind::String => FieldKind::String,
                        FieldKind::Bytes => FieldKind::Bytes,
                        FieldKind::Bool => FieldKind::Bool,
                        FieldKind::Float => FieldKind::Float,
                        FieldKind::Double => FieldKind::Double,
                        FieldKind::Int32 => FieldKind::Int32,
                        FieldKind::Int64 => FieldKind::Int64,
                        FieldKind::Sint32 => FieldKind::Sint32,
                        FieldKind::Sint64 => FieldKind::Sint64,
                        FieldKind::Sfixed32 => FieldKind::Sfixed32,
                        FieldKind::Sfixed64 => FieldKind::Sfixed64,
                        FieldKind::Uint32 => FieldKind::Uint32,
                        FieldKind::Uint64 => FieldKind::Uint64,
                        FieldKind::Fixed32 => FieldKind::Fixed32,
                        FieldKind::Fixed64 => FieldKind::Fixed64,
                        FieldKind::Enum { full_name } => FieldKind::Enum {
                            full_name: full_name.clone(),
                        },
                        _ => return None,
                    },
                };
                let (this_expr, this_ty) =
                    crate::emit::cel::this_binding_for_kind(&scalar_kind, &access)?;
                crate::emit::cel::try_compile_cel_check(
                    expr,
                    id,
                    msg,
                    this_expr,
                    this_ty,
                    rule.rule_const.as_ref(),
                    &fp_quote,
                    &rp_quote,
                    false,
                    schemas,
                )
            });
            if let Some(check) = native {
                out.push(quote! {
                    for (idx, elem) in self.#accessor.iter().enumerate() {
                        #check
                    }
                });
                continue;
            }
            // Unsupported predefined items rule — emit a runtime-error
            // marker so the user sees a clear runtime signal.
            let id_s = id.to_string();
            let expr_s = expr.to_string();
            out.push(crate::emit::cel::emit_runtime_error_violation(
                &id_s,
                &format!("unsupported predefined CEL (repeated items): {expr_s}"),
            ));
        }
    }

    // Per-element CEL rules (`repeated.items.cel`).
    if let Some(items) = &spec.items
        && !matches!(items.ignore, crate::scan::Ignore::Always)
        && !items.cel.is_empty()
    {
        let element_ty_ident = format_ident!("{}", element_type_variant);
        for (idx, rule) in items.cel.iter().enumerate() {
            let id = rule.id.as_str();
            let msg = rule.message.as_str();
            let expr = rule.expression.as_str();
            let idx_lit = idx as u64;
            let fp_quote = quote! {
                ::protovalidate_buffa::FieldPath {
                    elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                        field_number: Some(#field_number),
                        field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                        field_type: Some(::protovalidate_buffa::FieldType::#element_ty_ident),
                        key_type: None,
                        value_type: None,
                        subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                    }],
                }
            };
            let rp_quote = quote! {
                ::protovalidate_buffa::FieldPath {
                    elements: ::std::vec![
                        ::protovalidate_buffa::FieldPathElement { field_number: Some(18i32), field_name: Some(::std::borrow::Cow::Borrowed("repeated")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                        ::protovalidate_buffa::FieldPathElement { field_number: Some(4i32), field_name: Some(::std::borrow::Cow::Borrowed("items")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                        ::protovalidate_buffa::FieldPathElement { field_number: Some(23i32), field_name: Some(::std::borrow::Cow::Borrowed("cel")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: Some(::protovalidate_buffa::Subscript::Index(#idx_lit)) },
                    ],
                }
            };
            // Native path: bind `this` to the element value and transpile.
            let elem_access = match element_kind {
                FieldKind::String => Some(quote! { ::core::convert::AsRef::<str>::as_ref(elem) }),
                FieldKind::Bytes => Some(quote! { ::core::convert::AsRef::<[u8]>::as_ref(elem) }),
                FieldKind::Bool => Some(quote! { (*elem) }),
                FieldKind::Float
                | FieldKind::Double
                | FieldKind::Int32
                | FieldKind::Int64
                | FieldKind::Sint32
                | FieldKind::Sint64
                | FieldKind::Sfixed32
                | FieldKind::Sfixed64
                | FieldKind::Uint32
                | FieldKind::Uint64
                | FieldKind::Fixed32
                | FieldKind::Fixed64
                | FieldKind::Enum { .. } => Some(quote! { (*elem) }),
                FieldKind::Message { .. } => Some(quote! { elem }),
                _ => None,
            };
            let native = elem_access.and_then(|access| {
                let (this_expr, this_ty) = crate::emit::cel::this_binding_for_kind_with(
                    element_kind,
                    &access,
                    Some(schemas),
                )?;
                crate::emit::cel::try_compile_cel_check(
                    expr, id, msg, this_expr, this_ty, None, &fp_quote, &rp_quote, false, schemas,
                )
            });
            if let Some(check) = native {
                out.push(quote! {
                    for (idx, elem) in self.#accessor.iter().enumerate() {
                        #check
                    }
                });
                continue;
            }
            out.push(crate::emit::cel::emit_runtime_error_violation(
                id,
                &format!("unsupported CEL (repeated items): {expr}"),
            ));
        }
    }

    // Per-element message recursion. Skip google.protobuf.* (WKTs we don't
    // validate) and any cross-package messages where we can't guarantee an
    // impl Validate exists.
    if let FieldKind::Message { full_name } = element_kind
        && !full_name.starts_with("google.protobuf.")
    {
        let fnum = field_number;
        out.push(quote! {
            for (idx, elem) in self.#accessor.iter().enumerate() {
                if let Err(sub) = elem.validate() {
                    violations.extend(sub.violations.into_iter().map(|mut v| {
                        v.field.elements.insert(0, ::protovalidate_buffa::FieldPathElement {
                            field_number: Some(#fnum),
                            field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                            field_type: Some(::protovalidate_buffa::FieldType::Message),
                            key_type: None,
                            value_type: None,
                            subscript: Some(::protovalidate_buffa::Subscript::Index(idx as u64)),
                        });
                        v
                    }));
                }
            }
        });
    }

    Ok(quote! { #( #out )* })
}

// ─── map ─────────────────────────────────────────────────────────────────────

/// Emit the validation snippet for a `map` field.
///
/// Handles:
/// - `min_pairs` / `max_pairs` size checks.
/// - Per-key scalar rule application (`keys`).
/// - Per-value scalar rule application (`values`).
///
/// # Errors
///
/// Returns an error if the emitted `TokenStream` cannot be assembled (currently
/// infallible; reserved for future key/value emitters that may fail).
///
/// # Panics
///
/// Panics if `min_pairs` or `max_pairs` cannot be converted to `usize`. In
/// practice proto size bounds are small non-negative integers, so this
/// invariant always holds.
pub fn emit_map(
    map: &TokenStream,
    name_lit: &str,
    field_number: i32,
    spec: &MapStandard,
    key_kind: &FieldKind,
    value_kind: &FieldKind,
    schemas: &crate::emit::cel::SchemaIndex,
) -> Result<TokenStream> {
    let mut out: Vec<TokenStream> = Vec::new();
    let fp = || map_field_path(name_lit, field_number);

    if let Some(min) = spec.min_pairs {
        let min_usize = usize::try_from(min).expect("proto length bound fits in usize");
        let field = fp();
        let rule = map_rule_path("min_pairs", 1);
        out.push(quote! {
            if (#map).len() < #min_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("map.min_pairs"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "map must contain at least {} pairs (got {})",
                        #min_usize, (#map).len()
                    )),
                    for_key: false,
                });
            }
        });
    }

    if let Some(max) = spec.max_pairs {
        let max_usize = usize::try_from(max).expect("proto length bound fits in usize");
        let field = fp();
        let rule = map_rule_path("max_pairs", 2);
        out.push(quote! {
            if (#map).len() > #max_usize {
                violations.push(::protovalidate_buffa::Violation {
                    field: #field, rule: #rule,
                    rule_id: ::std::borrow::Cow::Borrowed("map.max_pairs"),
                    message: ::std::borrow::Cow::Owned(::std::format!(
                        "map must contain at most {} pairs (got {})",
                        #max_usize, (#map).len()
                    )),
                    for_key: false,
                });
            }
        });
    }

    let keys_always = spec
        .keys
        .as_deref()
        .is_some_and(|k| matches!(k.ignore, crate::scan::Ignore::Always));
    let values_always = spec
        .values
        .as_deref()
        .is_some_and(|v| matches!(v.ignore, crate::scan::Ignore::Always));
    let key_ty_variant = crate::emit::field::kind_to_field_type(key_kind);
    let val_ty_variant = crate::emit::field::kind_to_field_type(value_kind);

    let key_subscript = kind_variant_to_subscript(key_ty_variant);
    let entry_checks = |rules: Option<&crate::scan::FieldValidator>,
                        always: bool,
                        kind: &FieldKind,
                        ident: &syn::Ident,
                        for_key: bool|
     -> Result<Vec<TokenStream>> {
        let (Some(rules), false, Some(key_subscript)) = (rules, always, key_subscript.as_ref())
        else {
            return Ok(Vec::new());
        };
        let site = crate::emit::field::RuleSite::map_entry(
            name_lit,
            field_number,
            key_ty_variant,
            val_ty_variant,
            key_subscript,
            for_key,
        );
        crate::emit::field::emit_scalar_rules(
            &element_value(kind, ident),
            kind,
            &rules.standard,
            &site,
        )
    };
    let key_checks = entry_checks(
        spec.keys.as_deref(),
        keys_always,
        key_kind,
        &format_ident!("key"),
        true,
    )?;
    let val_checks = entry_checks(
        spec.values.as_deref(),
        values_always,
        value_kind,
        &format_ident!("value"),
        false,
    )?;

    let key_empty = spec
        .keys
        .as_deref()
        .is_some_and(|k| matches!(k.ignore, crate::scan::Ignore::IfZeroValue));
    let val_empty = spec
        .values
        .as_deref()
        .is_some_and(|v| matches!(v.ignore, crate::scan::Ignore::IfZeroValue));
    let key_guard = if key_empty {
        zero_guard(key_kind, &format_ident!("key"))
    } else {
        None
    };
    let val_guard = if val_empty {
        zero_guard(value_kind, &format_ident!("value"))
    } else {
        None
    };

    if !key_checks.is_empty() || !val_checks.is_empty() {
        let key_block = key_guard.as_ref().map_or_else(
            || quote! { #( #key_checks )* },
            |g| quote! { if #g { #( #key_checks )* } },
        );
        let val_block = val_guard.as_ref().map_or_else(
            || quote! { #( #val_checks )* },
            |g| quote! { if #g { #( #val_checks )* } },
        );
        out.push(quote! {
            for (key, value) in (#map).iter() {
                #key_block
                #val_block
            }
        });
    }

    // Per-key / per-value CEL rules.
    let key_ty_ident = format_ident!("{}", crate::emit::field::kind_to_field_type(key_kind));
    let val_ty_ident = format_ident!("{}", crate::emit::field::kind_to_field_type(value_kind));
    let emit_map_cel = |out: &mut Vec<TokenStream>,
                        rules: &[crate::scan::CelRule],
                        for_key: bool| {
        let Some(key_subscript) =
            kind_variant_to_subscript(crate::emit::field::kind_to_field_type(key_kind))
        else {
            return;
        };
        for (idx, rule) in rules.iter().enumerate() {
            let id = rule.id.as_str();
            let msg = rule.message.as_str();
            let expr = rule.expression.as_str();
            let idx_lit = idx as u64;
            let value_ident = format_ident!("{}", if for_key { "key" } else { "value" });
            let target_kind = if for_key { key_kind } else { value_kind };
            let kt = key_ty_ident.clone();
            let vt = val_ty_ident.clone();
            let ks = key_subscript.clone();
            let fp_quote = quote! {
                ::protovalidate_buffa::FieldPath {
                    elements: ::std::vec![::protovalidate_buffa::FieldPathElement {
                        field_number: Some(#field_number),
                        field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                        field_type: Some(::protovalidate_buffa::FieldType::Message),
                        key_type: Some(::protovalidate_buffa::FieldType::#kt),
                        value_type: Some(::protovalidate_buffa::FieldType::#vt),
                        subscript: Some(#ks),
                    }],
                }
            };
            // Rule path: map.<keys|values>.cel[idx]
            let leaf_name = if for_key { "keys" } else { "values" };
            let leaf_num = if for_key { 4i32 } else { 5i32 };
            let rp_quote = quote! {
                ::protovalidate_buffa::FieldPath {
                    elements: ::std::vec![
                        ::protovalidate_buffa::FieldPathElement { field_number: Some(19i32), field_name: Some(::std::borrow::Cow::Borrowed("map")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                        ::protovalidate_buffa::FieldPathElement { field_number: Some(#leaf_num), field_name: Some(::std::borrow::Cow::Borrowed(#leaf_name)), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: None },
                        ::protovalidate_buffa::FieldPathElement { field_number: Some(23i32), field_name: Some(::std::borrow::Cow::Borrowed("cel")), field_type: Some(::protovalidate_buffa::FieldType::Message), key_type: None, value_type: None, subscript: Some(::protovalidate_buffa::Subscript::Index(#idx_lit)) },
                    ],
                }
            };
            let access = match target_kind {
                FieldKind::String => {
                    Some(quote! { ::core::convert::AsRef::<str>::as_ref(#value_ident) })
                }
                FieldKind::Bytes => {
                    Some(quote! { ::core::convert::AsRef::<[u8]>::as_ref(#value_ident) })
                }
                FieldKind::Bool => Some(quote! { (*#value_ident) }),
                FieldKind::Float
                | FieldKind::Double
                | FieldKind::Int32
                | FieldKind::Int64
                | FieldKind::Sint32
                | FieldKind::Sint64
                | FieldKind::Sfixed32
                | FieldKind::Sfixed64
                | FieldKind::Uint32
                | FieldKind::Uint64
                | FieldKind::Fixed32
                | FieldKind::Fixed64
                | FieldKind::Enum { .. } => Some(quote! { (*#value_ident) }),
                FieldKind::Message { .. } => Some(quote! { #value_ident }),
                _ => None,
            };
            let native = access.and_then(|a| {
                let (this_expr, this_ty) =
                    crate::emit::cel::this_binding_for_kind_with(target_kind, &a, Some(schemas))?;
                crate::emit::cel::try_compile_cel_check(
                    expr, id, msg, this_expr, this_ty, None, &fp_quote, &rp_quote, for_key, schemas,
                )
            });
            if let Some(check) = native {
                out.push(quote! {
                    for (key, value) in (#map).iter() {
                        #check
                    }
                });
                continue;
            }
            out.push(crate::emit::cel::emit_runtime_error_violation(
                id,
                &format!("unsupported CEL (map): {expr}"),
            ));
        }
    };
    if let Some(k) = spec.keys.as_deref()
        && !matches!(k.ignore, crate::scan::Ignore::Always)
        && !k.cel.is_empty()
    {
        emit_map_cel(&mut out, &k.cel, true);
    }
    if let Some(v) = spec.values.as_deref()
        && !matches!(v.ignore, crate::scan::Ignore::Always)
        && !v.cel.is_empty()
    {
        emit_map_cel(&mut out, &v.cel, false);
    }

    // Recurse into message-typed map values so nested validators fire.
    if let FieldKind::Message { full_name } = value_kind
        && !full_name.starts_with("google.protobuf.")
    {
        let key_subscript_opt =
            kind_variant_to_subscript(crate::emit::field::kind_to_field_type(key_kind));
        if let Some(key_subscript) = key_subscript_opt {
            let kt = format_ident!("{}", crate::emit::field::kind_to_field_type(key_kind));
            let vt = format_ident!("{}", crate::emit::field::kind_to_field_type(value_kind));
            out.push(quote! {
                for (key, value) in (#map).iter() {
                    if let Err(sub) = value.validate() {
                        violations.extend(sub.violations.into_iter().map(|mut v| {
                            v.field.elements.insert(0, ::protovalidate_buffa::FieldPathElement {
                                field_number: Some(#field_number),
                                field_name: Some(::std::borrow::Cow::Borrowed(#name_lit)),
                                field_type: Some(::protovalidate_buffa::FieldType::Message),
                                key_type: Some(::protovalidate_buffa::FieldType::#kt),
                                value_type: Some(::protovalidate_buffa::FieldType::#vt),
                                subscript: Some(#key_subscript),
                            });
                            v
                        }));
                    }
                }
            });
        }
    }

    Ok(quote! { #( #out )* })
}

// ─── element values ──────────────────────────────────────────────────────────

/// The value an element binding (`&T`) contributes to the shared scalar rule
/// emitters: numeric and bool elements by value, the rest by reference.
fn element_value(kind: &FieldKind, ident: &syn::Ident) -> TokenStream {
    match kind {
        FieldKind::Int32
        | FieldKind::Sint32
        | FieldKind::Sfixed32
        | FieldKind::Int64
        | FieldKind::Sint64
        | FieldKind::Sfixed64
        | FieldKind::Uint32
        | FieldKind::Fixed32
        | FieldKind::Uint64
        | FieldKind::Fixed64
        | FieldKind::Float
        | FieldKind::Double
        | FieldKind::Bool => quote! { (*#ident) },
        _ => quote! { #ident },
    }
}

/// Zero-value guard for `IGNORE_IF_ZERO_VALUE` on items, keys, and values.
fn zero_guard(kind: &FieldKind, ident: &syn::Ident) -> Option<TokenStream> {
    match kind {
        FieldKind::String | FieldKind::Bytes => Some(quote! { !#ident.is_empty() }),
        FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
            Some(quote! { *#ident != 0i32 })
        }
        FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => {
            Some(quote! { *#ident != 0i64 })
        }
        FieldKind::Uint32 | FieldKind::Fixed32 => Some(quote! { *#ident != 0u32 }),
        FieldKind::Uint64 | FieldKind::Fixed64 => Some(quote! { *#ident != 0u64 }),
        FieldKind::Float => Some(quote! { *#ident != 0f32 }),
        FieldKind::Double => Some(quote! { *#ident != 0f64 }),
        FieldKind::Bool => Some(quote! { *#ident }),
        _ => None,
    }
}
