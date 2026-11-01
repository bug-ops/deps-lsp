//! Position-aware `pnpm-workspace.yaml` parser (spec 078).
//!
//! One event-stream pass over the document yields every `catalog:` / `catalogs.<name>:` entry
//! together with the exact source ranges of its key and version text. Both consumers read this
//! single interpretation of the file (spec NFR-004): the `package.json` side
//! ([`crate::catalog::PnpmWorkspaceConfig`], resolving `catalog:` references) and the
//! workspace-file side ([`parse_pnpm_workspace_manifest`], surfacing the entries themselves as
//! dependencies).
//!
//! Built on the shared `deps-core` YAML mechanics (`yaml_walk::FrameStack`,
//! `yaml_anchor::ScalarAnchorTable`, `MarkedScalar`) like the `deps-dart` receiver. Only the
//! first YAML document is read, matching pnpm. The `packages` globs and `overrides` entries are
//! read alongside the catalogs; a wrong-shaped `packages`/`overrides` section drops only that
//! section and never marks the catalogs malformed. Every other top-level key (settings) is
//! skipped structurally.
//!
//! # Known limitation
//!
//! An alias to an anchored *mapping* in a section position (`catalog: *shared`) is not
//! expanded; the section is reported as malformed rather than guessed at. An alias to an
//! anchored *scalar* as an entry value is supported.

use deps_core::lsp_helpers::{
    LineOffsetTable, MarkedScalar, byte_span_to_range, is_plain_null, marker_byte_offset,
};
use deps_core::position::Range;
use deps_core::yaml_anchor::{AnchorLimits, ScalarAnchorTable};
use deps_core::yaml_walk::{FrameKind, FrameStack, ScalarPosition};
use deps_core::{DepsError, Result};
use url::Url;
use yaml_rust2::Yaml;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

use crate::catalog::ConfigDefect;
use crate::config::NpmParseContext;
use crate::parser::NpmParseResult;
use crate::types::{
    CatalogId, CatalogSite, NpmDependency, NpmDependencyOrigin, OverrideSelector, OverrideValue,
};
use crate::workspace_members::{PackageGlob, WorkspaceMembers};

const FILE_LABEL: &str = "pnpm-workspace.yaml";

/// Upper bound on anchored scalar text kept for alias resolution; anything longer is never a
/// version range worth resolving.
const MAX_ANCHORED_SCALAR_CHARS: usize = deps_core::lsp_helpers::MAX_REQUIREMENT_LEN;

/// Upper bound on distinct anchors the alias table records.
const MAX_ANCHORS: usize = 4096;

/// How an entry's version text sits in the document, which decides what may be done with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EntryValue {
    /// A scalar usable as a version specifier.
    Text {
        /// The scalar's text (for an alias, the anchored scalar's text).
        text: String,
        /// Range of exactly the bytes a replacement would overwrite (quotes excluded); the
        /// alias token span for an alias. `None` when the scalar cannot be located
        /// unambiguously (block scalars, escaped quoted scalars): findings need a range, so
        /// such an entry gets none and, by construction, no edit.
        range: Option<Range>,
    },
    /// The entry has a key and an empty value (`lodash:` or `{lodash: }`), the state of an
    /// entry still being typed. It becomes a dependency with no requirement so version
    /// completion can offer versions at `at`, but it carries no finding and no edit.
    Empty {
        /// Zero-width position right after the `:` and any spaces following it.
        at: Range,
    },
    /// The entry exists but its value is not a version string (a mapping, sequence, `~`/`null`,
    /// boolean or non-string tagged scalar).
    Unusable,
}

/// One catalog entry with the positions of its key and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceEntry {
    pub(crate) id: CatalogId,
    pub(crate) site: CatalogSite,
    pub(crate) name: String,
    pub(crate) name_range: Option<Range>,
    pub(crate) value: EntryValue,
}

/// One `overrides:` entry with the positions of its key and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverrideEntry {
    pub(crate) key: String,
    pub(crate) key_range: Option<Range>,
    pub(crate) value: EntryValue,
}

/// Upper bound on `packages:` entries read from one file.
const MAX_PACKAGE_GLOBS: usize = 1000;

/// Everything catalog-relevant in one `pnpm-workspace.yaml`.
#[derive(Debug, Default)]
pub(crate) struct WorkspaceDocument {
    pub(crate) entries: Vec<WorkspaceEntry>,
    /// Set when the file is unusable for catalog resolution (wrong-shaped section, or the
    /// default catalog defined twice). Entries are cleared for [`ConfigDefect::Malformed`]
    /// and kept for [`ConfigDefect::DuplicateDefaultCatalog`].
    pub(crate) defect: Option<ConfigDefect>,
    /// Range of the `catalogs.default` key, the anchor of the duplicate-default diagnostic.
    pub(crate) duplicate_default_key: Option<Range>,
    /// The parsed `packages:` entries; `None` when the section is absent or wrong-shaped, in
    /// which case pnpm's default (every subdirectory) applies.
    pub(crate) package_globs: Option<Vec<PackageGlob>>,
    /// Set when `packages:` listed more than `MAX_PACKAGE_GLOBS` entries and the rest were dropped.
    pub(crate) package_globs_truncated: bool,
    /// The `overrides:` entries, kept apart so catalog resolution never sees them.
    pub(crate) overrides: Vec<OverrideEntry>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FrameRole {
    Root,
    CatalogsSection,
    CatalogEntries,
    PackagesSection,
    OverridesEntries,
    Irrelevant,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum PendingKey {
    #[default]
    None,
    Catalog,
    Catalogs,
    Packages,
    Overrides,
}

#[derive(Default)]
struct FramePayload {
    /// Keys already seen in this mapping; a repeat makes the file malformed, like pnpm.
    keys: std::collections::HashSet<String>,
    pending_name: Option<MarkedScalar>,
    catalog: Option<(CatalogId, CatalogSite)>,
}

type Stack = FrameStack<FrameRole, PendingKey, FramePayload>;

enum TextForm {
    Literal,
    Alias,
    Block,
}

enum RawValue {
    Empty,
    Text {
        scalar: MarkedScalar,
        form: TextForm,
    },
    Unusable,
}

struct RawEntry {
    id: CatalogId,
    site: CatalogSite,
    name: MarkedScalar,
    value: RawValue,
}

/// What the receiver has seen of the root `packages` key.
enum PackagesState {
    Absent,
    Listed {
        globs: Vec<String>,
        overflowed: bool,
    },
    Wrong,
}

struct RawOverride {
    key: MarkedScalar,
    value: RawValue,
}

struct Receiver {
    stack: Stack,
    anchors: ScalarAnchorTable<(TScalarStyle, Option<Tag>)>,
    entries: Vec<RawEntry>,
    overrides: Vec<RawOverride>,
    overrides_bad: bool,
    packages: PackagesState,
    malformed: bool,
    top_level_catalog: bool,
    default_key: Option<MarkedScalar>,
}

impl Receiver {
    fn new() -> Self {
        Self {
            stack: Stack::new(),
            anchors: ScalarAnchorTable::new(AnchorLimits::bounded(
                MAX_ANCHORED_SCALAR_CHARS,
                MAX_ANCHORS,
            )),
            entries: Vec::new(),
            overrides: Vec::new(),
            overrides_bad: false,
            packages: PackagesState::Absent,
            malformed: false,
            top_level_catalog: false,
            default_key: None,
        }
    }

    fn push_container(&mut self, kind: FrameKind) {
        let (role, payload) = self.child_role(kind);
        self.stack.push(kind, role, payload);
    }

    fn child_role(&mut self, kind: FrameKind) -> (FrameRole, FramePayload) {
        let irrelevant = (FrameRole::Irrelevant, FramePayload::default());
        match self.stack.scalar_position() {
            ScalarPosition::Outside => {
                if self.stack.depth() == 0 && kind == FrameKind::Mapping {
                    (FrameRole::Root, FramePayload::default())
                } else {
                    if self.stack.top_role_or(FrameRole::Irrelevant) == FrameRole::PackagesSection {
                        self.packages = PackagesState::Wrong;
                    }
                    irrelevant
                }
            }
            // A container where a key is expected is a complex key; never a section.
            ScalarPosition::Key => irrelevant,
            ScalarPosition::Value => {
                let role = self.stack.top_role_or(FrameRole::Irrelevant);
                let pending = self
                    .stack
                    .top()
                    .map_or(PendingKey::None, |frame| *frame.pending_key());
                let name = self
                    .stack
                    .top_mut()
                    .and_then(|frame| frame.payload.pending_name.take());
                match (role, kind) {
                    (FrameRole::Root, FrameKind::Mapping) => match pending {
                        PendingKey::Catalog => {
                            self.top_level_catalog = true;
                            entries_frame(CatalogId::Default, CatalogSite::TopLevelCatalog)
                        }
                        PendingKey::Catalogs => {
                            (FrameRole::CatalogsSection, FramePayload::default())
                        }
                        PendingKey::Overrides => {
                            (FrameRole::OverridesEntries, FramePayload::default())
                        }
                        PendingKey::Packages => {
                            self.packages = PackagesState::Wrong;
                            irrelevant
                        }
                        PendingKey::None => irrelevant,
                    },
                    (FrameRole::Root, FrameKind::Sequence) => match pending {
                        PendingKey::Packages => {
                            self.packages = PackagesState::Listed {
                                globs: Vec::new(),
                                overflowed: false,
                            };
                            (FrameRole::PackagesSection, FramePayload::default())
                        }
                        PendingKey::Overrides => {
                            self.overrides_bad = true;
                            irrelevant
                        }
                        PendingKey::Catalog | PendingKey::Catalogs => {
                            self.malformed = true;
                            irrelevant
                        }
                        PendingKey::None => irrelevant,
                    },
                    (FrameRole::CatalogsSection, FrameKind::Mapping) => {
                        let Some(name) = name.filter(|name| !name.text().is_empty()) else {
                            return irrelevant;
                        };
                        let id = CatalogId::from_name(name.text());
                        let site = match id {
                            CatalogId::Default => CatalogSite::CatalogsDefault,
                            CatalogId::Named(_) => CatalogSite::CatalogsNamed,
                        };
                        if id == CatalogId::Default {
                            self.default_key = Some(name);
                        }
                        entries_frame(id, site)
                    }
                    (FrameRole::CatalogsSection, FrameKind::Sequence) => {
                        self.malformed = true;
                        irrelevant
                    }
                    (FrameRole::CatalogEntries, _) => {
                        if let (Some(name), Some(catalog)) = (name, self.current_catalog()) {
                            self.entries.push(RawEntry {
                                id: catalog.0,
                                site: catalog.1,
                                name,
                                value: RawValue::Unusable,
                            });
                        }
                        irrelevant
                    }
                    (
                        FrameRole::OverridesEntries
                        | FrameRole::PackagesSection
                        | FrameRole::Irrelevant,
                        _,
                    ) => irrelevant,
                }
            }
        }
    }

    fn current_catalog(&self) -> Option<(CatalogId, CatalogSite)> {
        self.stack
            .top()
            .and_then(|frame| frame.payload.catalog.clone())
    }

    fn on_scalar(
        &mut self,
        value: String,
        style: TScalarStyle,
        anchor_id: usize,
        tag: Option<Tag>,
        marker: &Marker,
    ) {
        if anchor_id != 0 {
            self.anchors.record(anchor_id, &value, (style, tag.clone()));
        }
        match self.stack.scalar_position() {
            ScalarPosition::Outside => self.on_sequence_scalar(value),
            ScalarPosition::Key => self.on_key(value, style, marker),
            ScalarPosition::Value => {
                let raw = classify_text(value, style, tag.as_ref(), marker, TextForm::Literal);
                self.on_value(raw);
            }
        }
    }

    fn on_sequence_scalar(&mut self, value: String) {
        if self.stack.top_role_or(FrameRole::Irrelevant) == FrameRole::PackagesSection
            && let PackagesState::Listed { globs, overflowed } = &mut self.packages
        {
            if globs.len() < MAX_PACKAGE_GLOBS {
                globs.push(value);
            } else {
                *overflowed = true;
            }
        }
    }

    fn on_key(&mut self, value: String, style: TScalarStyle, marker: &Marker) {
        let role = self.stack.top_role_or(FrameRole::Irrelevant);
        if !matches!(role, FrameRole::Irrelevant | FrameRole::PackagesSection)
            && let Some(top) = self.stack.top_mut()
            && !top.payload.keys.insert(value.clone())
        {
            if role == FrameRole::OverridesEntries {
                self.overrides_bad = true;
            } else {
                self.malformed = true;
            }
        }
        match role {
            FrameRole::Root => {
                // The scanner keeps a leading BOM in the first key's text.
                let key = match value.trim_start_matches('\u{feff}') {
                    "catalog" => PendingKey::Catalog,
                    "catalogs" => PendingKey::Catalogs,
                    "packages" => PendingKey::Packages,
                    "overrides" => PendingKey::Overrides,
                    _ => PendingKey::None,
                };
                self.stack.observe_key(key);
            }
            FrameRole::CatalogsSection
            | FrameRole::CatalogEntries
            | FrameRole::OverridesEntries => {
                if let Some(top) = self.stack.top_mut() {
                    top.payload.pending_name = Some(MarkedScalar::new(value, style, marker));
                }
                self.stack.observe_key(PendingKey::None);
            }
            FrameRole::PackagesSection | FrameRole::Irrelevant => {
                self.stack.observe_key(PendingKey::None);
            }
        }
    }

    /// Consumes a scalar (or resolved alias) in value position.
    fn on_value(&mut self, raw: Classified) {
        let role = self.stack.top_role_or(FrameRole::Irrelevant);
        match role {
            FrameRole::Root => {
                let pending = self
                    .stack
                    .top()
                    .map_or(PendingKey::None, |frame| *frame.pending_key());
                if !matches!(raw, Classified::Null | Classified::Empty) {
                    match pending {
                        PendingKey::Catalog | PendingKey::Catalogs => self.malformed = true,
                        PendingKey::Packages => self.packages = PackagesState::Wrong,
                        PendingKey::Overrides => self.overrides_bad = true,
                        PendingKey::None => {}
                    }
                }
            }
            FrameRole::CatalogsSection => {
                if let Some(top) = self.stack.top_mut() {
                    top.payload.pending_name = None;
                }
                if !matches!(raw, Classified::Null | Classified::Empty) {
                    self.malformed = true;
                }
            }
            FrameRole::CatalogEntries => {
                let name = self
                    .stack
                    .top_mut()
                    .and_then(|frame| frame.payload.pending_name.take());
                if let (Some(name), Some((id, site))) = (name, self.current_catalog()) {
                    let value = match raw {
                        Classified::Text { scalar, form } => RawValue::Text { scalar, form },
                        Classified::Empty => RawValue::Empty,
                        Classified::Null | Classified::Unusable => RawValue::Unusable,
                    };
                    self.entries.push(RawEntry {
                        id,
                        site,
                        name,
                        value,
                    });
                }
            }
            FrameRole::OverridesEntries => {
                let key = self
                    .stack
                    .top_mut()
                    .and_then(|frame| frame.payload.pending_name.take());
                if let Some(key) = key {
                    let value = match raw {
                        Classified::Text { scalar, form } => RawValue::Text { scalar, form },
                        Classified::Empty => RawValue::Empty,
                        Classified::Null | Classified::Unusable => RawValue::Unusable,
                    };
                    self.overrides.push(RawOverride { key, value });
                }
            }
            FrameRole::PackagesSection | FrameRole::Irrelevant => {}
        }
        self.stack.consume_value();
    }

    fn on_alias(&mut self, anchor_id: usize, marker: &Marker) {
        match self.stack.scalar_position() {
            ScalarPosition::Outside => {}
            ScalarPosition::Key => self.stack.observe_key(PendingKey::None),
            ScalarPosition::Value => {
                let raw = match self.anchors.get(anchor_id) {
                    Some((text, (style, tag))) => classify_text(
                        text.to_string(),
                        *style,
                        tag.as_ref(),
                        marker,
                        TextForm::Alias,
                    ),
                    // An unrecorded anchor: a container (not expanded, see the module docs) or
                    // a scalar beyond the anchor bounds.
                    None => match self.stack.top_role_or(FrameRole::Irrelevant) {
                        FrameRole::CatalogEntries
                        | FrameRole::OverridesEntries
                        | FrameRole::PackagesSection
                        | FrameRole::Irrelevant => Classified::Unusable,
                        FrameRole::Root | FrameRole::CatalogsSection => {
                            self.malformed = true;
                            Classified::Null
                        }
                    },
                };
                self.on_value(raw);
            }
        }
    }
}

fn entries_frame(id: CatalogId, site: CatalogSite) -> (FrameRole, FramePayload) {
    (
        FrameRole::CatalogEntries,
        FramePayload {
            catalog: Some((id, site)),
            ..FramePayload::default()
        },
    )
}

enum Classified {
    Null,
    Empty,
    Unusable,
    Text {
        scalar: MarkedScalar,
        form: TextForm,
    },
}

fn is_str_tag(tag: &Tag) -> bool {
    (tag.handle == "tag:yaml.org,2002:" && tag.suffix == "str")
        || (tag.handle.is_empty() && tag.suffix == "tag:yaml.org,2002:str")
}

/// Classifies a scalar in value position the way the previous `YamlLoader`-based parser did:
/// a plain scalar that resolves to a boolean is not a version string (issue #721 keeps
/// numeric-looking ones), a quoted one always is. The raw event text is kept (not the
/// re-stringified number) so the range lookup matches the source bytes.
fn classify_text(
    text: String,
    style: TScalarStyle,
    tag: Option<&Tag>,
    marker: &Marker,
    form: TextForm,
) -> Classified {
    if is_plain_null(style, tag, &text) {
        let still_being_typed =
            text.is_empty() && tag.is_none() && matches!(form, TextForm::Literal);
        return if still_being_typed {
            Classified::Empty
        } else {
            Classified::Null
        };
    }
    let usable = match tag {
        Some(tag) => is_str_tag(tag),
        None if style == TScalarStyle::Plain => matches!(
            Yaml::from_str(&text),
            Yaml::String(_) | Yaml::Real(_) | Yaml::Integer(_)
        ),
        None => true,
    };
    if !usable {
        return Classified::Unusable;
    }
    let form = if matches!(style, TScalarStyle::Literal | TScalarStyle::Folded) {
        TextForm::Block
    } else {
        form
    };
    Classified::Text {
        scalar: MarkedScalar::new(text, style, marker),
        form,
    }
}

impl MarkedEventReceiver for Receiver {
    fn on_event(&mut self, event: Event, marker: Marker) {
        match event {
            Event::MappingStart(..) => self.push_container(FrameKind::Mapping),
            Event::SequenceStart(..) => self.push_container(FrameKind::Sequence),
            Event::MappingEnd | Event::SequenceEnd => {
                self.stack.pop();
            }
            Event::Scalar(value, style, anchor, tag) => {
                self.on_scalar(value, style, anchor, tag, &marker);
            }
            Event::Alias(anchor) => self.on_alias(anchor, &marker),
            Event::DocumentStart | Event::DocumentEnd => self.stack.clear(),
            Event::Nothing | Event::StreamStart | Event::StreamEnd => {}
        }
    }
}

/// Range of exactly the version text a replacement must overwrite, or `None` when the scalar
/// cannot be located without ambiguity.
///
/// A plain scalar must start at the scanner marker; a quoted one must be bounded by its own
/// quote bytes, which rules out matching decoded text inside an escape sequence.
fn literal_range(scalar: &MarkedScalar, content: &str, table: &LineOffsetTable) -> Option<Range> {
    let (start, end) = scalar.span(content, table)?;
    let bytes = content.as_bytes();
    if scalar.is_plain() {
        let marker_start = marker_byte_offset(content, table, scalar.line(), scalar.col());
        return (start == marker_start).then(|| byte_span_to_range(content, table, start, end));
    }
    let quote = match scalar.style() {
        TScalarStyle::SingleQuoted => b'\'',
        TScalarStyle::DoubleQuoted => b'"',
        TScalarStyle::Plain | TScalarStyle::Literal | TScalarStyle::Folded => return None,
    };
    let before = start.checked_sub(1).and_then(|i| bytes.get(i));
    let after = bytes.get(end);
    (before == Some(&quote) && after == Some(&quote))
        .then(|| byte_span_to_range(content, table, start, end))
}

/// Range of the `|`/`>` indicator token heading a block scalar.
///
/// The scanner marker of a block scalar points at its first content line, so the header is
/// found by walking back over blank lines to the nearest non-blank line and taking its last
/// token. Anchoring findings on the header rather than the content keeps the range from
/// matching the version text, so the shared edit guard offers no rewrite (spec 078 FR-032).
fn block_indicator_range(
    scalar: &MarkedScalar,
    content: &str,
    table: &LineOffsetTable,
) -> Option<Range> {
    let marker = marker_byte_offset(content, table, scalar.line(), scalar.col());
    let mut upto = content
        .get(..marker)?
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    for _ in 0..MAX_BLOCK_HEADER_LOOKBACK {
        let before = content.get(..upto)?.trim_end_matches(['\n', '\r']);
        let line_start = before.rfind('\n').map_or(0, |newline| newline + 1);
        let line = before.get(line_start..)?.trim_end();
        if line.is_empty() {
            upto = line_start;
            continue;
        }
        let token = line.rsplit(char::is_whitespace).next()?;
        token.starts_with(['|', '>']).then_some(())?;
        let start = line_start + line.len() - token.len();
        return Some(byte_span_to_range(
            content,
            table,
            start,
            start + token.len(),
        ));
    }
    None
}

/// How many blank lines a block scalar's header may be separated from its content by.
const MAX_BLOCK_HEADER_LOOKBACK: usize = 8;

/// Range of the `*alias` token the scanner marker points at, which must start with `lead`.
fn token_range(
    scalar: &MarkedScalar,
    content: &str,
    table: &LineOffsetTable,
    lead: &[char],
) -> Option<Range> {
    let start = marker_byte_offset(content, table, scalar.line(), scalar.col());
    let rest = content.get(start..)?;
    rest.starts_with(lead).then_some(())?;
    let len = rest
        .find(|c: char| c.is_whitespace() || matches!(c, ',' | ']' | '}'))
        .unwrap_or(rest.len());
    Some(byte_span_to_range(content, table, start, start + len))
}

/// Zero-width position right after the `:` following `name` and the spaces after it, where a
/// version typed for an empty entry would go.
fn empty_value_position(
    name: &MarkedScalar,
    content: &str,
    table: &LineOffsetTable,
) -> Option<Range> {
    let (_, name_end) = name.span(content, table)?;
    let rest = content.get(name_end..)?;
    let after_key = if name.is_quoted() {
        rest.get(1..)?
    } else {
        rest
    };
    let after_colon = after_key
        .trim_start_matches([' ', '\t'])
        .strip_prefix(':')?;
    let spaces = after_colon.len() - after_colon.trim_start_matches([' ', '\t']).len();
    let at = content.len() - after_colon.len() + spaces;
    Some(byte_span_to_range(content, table, at, at))
}

/// Turns a raw value into the positioned [`EntryValue`] the consumers read.
fn resolve_value(
    name: &MarkedScalar,
    value: RawValue,
    content: &str,
    table: &LineOffsetTable,
) -> EntryValue {
    match value {
        RawValue::Unusable => EntryValue::Unusable,
        RawValue::Empty => empty_value_position(name, content, table)
            .map_or(EntryValue::Unusable, |at| EntryValue::Empty { at }),
        RawValue::Text { scalar, form } => {
            let range = match form {
                TextForm::Literal => literal_range(&scalar, content, table),
                TextForm::Alias => token_range(&scalar, content, table, &['*']),
                TextForm::Block => block_indicator_range(&scalar, content, table),
            };
            let text = scalar.into_text();
            EntryValue::Text {
                text: if matches!(form, TextForm::Block) {
                    text.trim().to_string()
                } else {
                    text
                },
                range,
            }
        }
    }
}

fn finalize(receiver: Receiver, content: &str) -> WorkspaceDocument {
    let table = LineOffsetTable::new(content);
    let (package_globs, package_globs_truncated) = match receiver.packages {
        PackagesState::Listed { globs, overflowed } => (
            Some(globs.iter().filter_map(|g| PackageGlob::parse(g)).collect()),
            overflowed,
        ),
        PackagesState::Absent | PackagesState::Wrong => (None, false),
    };
    let overrides = if receiver.overrides_bad {
        Vec::new()
    } else {
        receiver
            .overrides
            .into_iter()
            .map(|raw| OverrideEntry {
                key_range: raw.key.range(content, &table),
                value: resolve_value(&raw.key, raw.value, content, &table),
                key: raw.key.into_text(),
            })
            .collect()
    };
    if receiver.malformed {
        return WorkspaceDocument {
            entries: Vec::new(),
            defect: Some(ConfigDefect::Malformed),
            duplicate_default_key: None,
            package_globs,
            package_globs_truncated,
            overrides,
        };
    }
    let duplicate = receiver.top_level_catalog && receiver.default_key.is_some();
    let duplicate_default_key = duplicate
        .then(|| {
            receiver
                .default_key
                .as_ref()
                .and_then(|key| key.range(content, &table))
        })
        .flatten();
    let entries = receiver
        .entries
        .into_iter()
        .map(|raw| WorkspaceEntry {
            id: raw.id,
            site: raw.site,
            name_range: raw.name.range(content, &table),
            value: resolve_value(&raw.name, raw.value, content, &table),
            name: raw.name.into_text(),
        })
        .collect();
    WorkspaceDocument {
        entries,
        defect: duplicate.then_some(ConfigDefect::DuplicateDefaultCatalog),
        duplicate_default_key,
        package_globs,
        package_globs_truncated,
        overrides,
    }
}

/// Parses `content` into a [`WorkspaceDocument`].
///
/// # Errors
///
/// Returns an error when the document exceeds the YAML depth/expansion bounds or is not
/// syntactically valid YAML. A syntactically valid document with a wrong-shaped section is
/// `Ok` with [`ConfigDefect::Malformed`] instead.
pub(crate) fn parse_workspace_document(content: &str) -> Result<WorkspaceDocument> {
    deps_core::check_yaml_bounds(content, FILE_LABEL)?;
    let mut receiver = Receiver::new();
    Parser::new_from_str(content)
        .load(&mut receiver, false)
        .map_err(|e| DepsError::parse_error(FILE_LABEL, &e))?;
    Ok(finalize(receiver, content))
}

/// Parses a `pnpm-workspace.yaml` as a dependency file: every registry-resolvable catalog
/// entry becomes an [`NpmDependency`] positioned on its own version text (spec 078).
///
/// Entries whose value is not a version string are skipped without failing the rest of the
/// file. A document defining the default catalog twice still yields its entries and records
/// the `catalogs.default` key range in [`NpmParseResult::duplicate_default_catalog`].
///
/// # Errors
///
/// Returns an error when the YAML exceeds the depth/expansion bounds or is syntactically
/// invalid, so no entry-level findings replace the previous stable results while the file
/// is mid-edit.
///
/// # Examples
///
/// ```no_run
/// use deps_npm::config::NpmParseContext;
/// use deps_npm::workspace::parse_pnpm_workspace_manifest;
/// use url::Url;
///
/// let uri = Url::from_file_path("/repo/pnpm-workspace.yaml").unwrap();
/// let result =
///     parse_pnpm_workspace_manifest("catalog:\n  react: ^18.0.0\n", &uri, &NpmParseContext::default())
///         .unwrap();
/// assert_eq!(result.dependencies.len(), 1);
/// ```
pub fn parse_pnpm_workspace_manifest(
    content: &str,
    uri: &Url,
    ctx: &NpmParseContext,
) -> Result<NpmParseResult> {
    let document = parse_workspace_document(content)?;
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);
    let mut dependencies = Vec::new();
    for entry in document.entries {
        let origin = NpmDependencyOrigin::CatalogEntry {
            id: entry.id,
            site: entry.site,
        };
        push_dependency(
            &mut dependencies,
            &mut budget,
            entry.name.as_str().into(),
            entry.name_range,
            entry.value,
            origin,
        );
    }
    for entry in document.overrides {
        let Some((target, selector)) = OverrideSelector::parse(&entry.key) else {
            continue;
        };
        if let EntryValue::Text { text, .. } = &entry.value
            && OverrideValue::classify(text) != OverrideValue::Range
        {
            continue;
        }
        push_dependency(
            &mut dependencies,
            &mut budget,
            target,
            entry.key_range,
            entry.value,
            NpmDependencyOrigin::Override { selector },
        );
    }

    let registries = crate::parser::resolve_dependency_sources(&mut dependencies, uri, ctx);
    Ok(NpmParseResult {
        dependencies,
        uri: uri.clone(),
        resolved_registries: registries.resolved,
        blocked_registries: registries.blocked,
        rejected_registries: registries.rejected,
        dependency_truncation: budget.truncation(),
        duplicate_default_catalog: document
            .defect
            .filter(|defect| *defect == ConfigDefect::DuplicateDefaultCatalog)
            .and(document.duplicate_default_key),
        workspace_members: crate::parser::manifest_directory(uri).map(|root| {
            let members = WorkspaceMembers::new(
                root,
                document.package_globs.unwrap_or_else(PackageGlob::defaults),
            );
            if document.package_globs_truncated {
                members.with_truncated_globs()
            } else {
                members
            }
        }),
    })
}

/// Appends one dependency for a positioned workspace-file entry, splitting an `npm:` alias.
fn push_dependency(
    dependencies: &mut Vec<NpmDependency>,
    budget: &mut deps_core::DependencyBudget,
    name: deps_core::PackageName,
    name_range: Option<Range>,
    value: EntryValue,
    origin: NpmDependencyOrigin,
) {
    let (package, version_req, range) = match value {
        EntryValue::Text { text, range } => match crate::parser::parse_npm_alias(&text) {
            Some(alias) => (Some(alias.package.into()), Some(alias.version_req), range),
            None => (None, Some(text), range),
        },
        EntryValue::Empty { at } => (None, None, Some(at)),
        EntryValue::Unusable => return,
    };
    if !budget.allow() {
        return;
    }
    dependencies.push(NpmDependency {
        name,
        name_range: name_range.unwrap_or_default(),
        version_req: version_req.map(Into::into),
        version_range: range,
        origin,
        source: deps_core::parser::DependencySource::Registry,
        package,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn uri() -> Url {
        deps_core::test_util::test_uri("/repo/pnpm-workspace.yaml")
    }

    /// The text a single-line `range` covers in `content`, counting UTF-16 code units like LSP.
    fn text_at(content: &str, range: Range) -> String {
        assert_eq!(
            range.start.line, range.end.line,
            "single-line range expected"
        );
        let line = content
            .split('\n')
            .nth(range.start.line as usize)
            .expect("range line exists")
            .trim_end_matches('\r');
        let mut utf16 = 0u32;
        let mut out = String::new();
        for ch in line.chars() {
            if utf16 >= range.start.character && utf16 < range.end.character {
                out.push(ch);
            }
            utf16 += u32::try_from(ch.len_utf16()).unwrap();
        }
        out
    }

    fn document(content: &str) -> WorkspaceDocument {
        parse_workspace_document(content).expect("valid yaml")
    }

    fn entry<'a>(doc: &'a WorkspaceDocument, name: &str) -> &'a WorkspaceEntry {
        doc.entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("entry {name} not found"))
    }

    fn version_text(content: &str, doc: &WorkspaceDocument, name: &str) -> Option<String> {
        match &entry(doc, name).value {
            EntryValue::Text { range, .. } => range.map(|r| text_at(content, r)),
            EntryValue::Empty { .. } | EntryValue::Unusable => None,
        }
    }

    fn manifest(content: &str) -> NpmParseResult {
        parse_pnpm_workspace_manifest(content, &uri(), &NpmParseContext::default()).unwrap()
    }

    #[test]
    fn test_default_catalog_entries_are_positioned() {
        let content = "catalog:\n  react: ^16.0.0\n  lodash: 4.17.0\n";
        let doc = document(content);
        assert_eq!(doc.entries.len(), 2);
        let react = entry(&doc, "react");
        assert_eq!(react.id, CatalogId::Default);
        assert_eq!(react.site, CatalogSite::TopLevelCatalog);
        assert_eq!(text_at(content, react.name_range.unwrap()), "react");
        assert_eq!(
            version_text(content, &doc, "react").as_deref(),
            Some("^16.0.0")
        );
        assert_eq!(
            version_text(content, &doc, "lodash").as_deref(),
            Some("4.17.0")
        );
    }

    #[test]
    fn test_named_and_catalogs_default_sites() {
        let content =
            "catalogs:\n  default:\n    react: ^18.0.0\n  legacy:\n    left-pad: ^1.0.0\n";
        let doc = document(content);
        let react = entry(&doc, "react");
        assert_eq!(react.id, CatalogId::Default);
        assert_eq!(react.site, CatalogSite::CatalogsDefault);
        let left_pad = entry(&doc, "left-pad");
        assert_eq!(left_pad.id, CatalogId::from_name("legacy"));
        assert_eq!(left_pad.site, CatalogSite::CatalogsNamed);
        assert_eq!(doc.defect, None);
    }

    #[test]
    fn test_same_package_in_two_catalogs_is_reported_at_each_location() {
        let content = "catalog:\n  react: ^18.0.0\ncatalogs:\n  legacy:\n    react: ^16.0.0\n";
        let doc = document(content);
        let reacts: Vec<_> = doc.entries.iter().filter(|e| e.name == "react").collect();
        assert_eq!(reacts.len(), 2);
        assert_ne!(reacts[0].id, reacts[1].id);
    }

    #[test]
    fn test_catalog_named_default_in_catalogs_is_the_default_catalog_not_a_named_one() {
        assert_eq!(CatalogId::from_name("default"), CatalogId::Default);
        let doc = document("catalogs:\n  default:\n    react: ^1.0.0\n");
        assert_eq!(entry(&doc, "react").id, CatalogId::Default);
    }

    #[test]
    fn test_quoting_styles_exclude_the_quotes_from_the_range() {
        let content = "catalog:\n  a: \"^1.0.0\"\n  b: '^2.0.0'\n  c: ^3.0.0\n  d: 1.2\n";
        let doc = document(content);
        assert_eq!(version_text(content, &doc, "a").as_deref(), Some("^1.0.0"));
        assert_eq!(version_text(content, &doc, "b").as_deref(), Some("^2.0.0"));
        assert_eq!(version_text(content, &doc, "c").as_deref(), Some("^3.0.0"));
        assert_eq!(version_text(content, &doc, "d").as_deref(), Some("1.2"));
    }

    #[test]
    fn test_flow_style_mappings() {
        let content = "catalog: {react: ^16.0.0, \"lodash\": '4.17.0'}\n";
        let doc = document(content);
        assert_eq!(
            version_text(content, &doc, "react").as_deref(),
            Some("^16.0.0")
        );
        assert_eq!(
            version_text(content, &doc, "lodash").as_deref(),
            Some("4.17.0")
        );
    }

    #[test]
    fn test_crlf_bom_non_ascii_and_comments() {
        let content =
            "\u{feff}catalog:\r\n  # ключ\r\n  \"réact\": ^16.0.0 # ✓\r\n  lodash: 4.17.0\r\n";
        let doc = document(content);
        assert_eq!(
            version_text(content, &doc, "réact").as_deref(),
            Some("^16.0.0")
        );
        assert_eq!(
            version_text(content, &doc, "lodash").as_deref(),
            Some("4.17.0")
        );
        let name = entry(&doc, "réact").name_range.unwrap();
        assert_eq!(text_at(content, name), "réact");
    }

    #[test]
    fn test_only_first_document_is_read() {
        let content = "catalog:\n  react: ^1.0.0\n---\ncatalog:\n  vue: ^3.0.0\n";
        let doc = document(content);
        assert_eq!(doc.entries.len(), 1);
        assert_eq!(doc.entries[0].name, "react");
    }

    #[test]
    fn test_overrides_stay_apart_from_catalog_entries_and_other_sections_are_ignored() {
        let content = "packages:\n  - 'pkgs/*'\noverrides:\n  'a>b': ^1.0.0\n  'pkg@^2': ^3.0.0\nonlyBuiltDependencies:\n  - esbuild\ncatalog:\n  react: ^18.0.0\n";
        let doc = document(content);
        assert_eq!(doc.entries.len(), 1);
        assert_eq!(doc.entries[0].name, "react");
        assert_eq!(doc.overrides.len(), 2);
    }

    #[test]
    fn test_non_scalar_entry_is_unusable_and_rest_survive() {
        let content = "catalog:\n  react:\n    version: ^18\n  seq:\n    - a\n  lodash: ^4.0.0\n";
        let doc = document(content);
        assert_matches!(entry(&doc, "react").value, EntryValue::Unusable);
        assert_matches!(entry(&doc, "seq").value, EntryValue::Unusable);
        assert_eq!(
            version_text(content, &doc, "lodash").as_deref(),
            Some("^4.0.0")
        );
        assert_eq!(doc.defect, None);
    }

    #[test]
    fn test_boolean_and_null_entries_are_unusable() {
        let doc = document("catalog:\n  a: true\n  b: ~\n  c:\n  d: ^1.0.0\n");
        assert_matches!(entry(&doc, "a").value, EntryValue::Unusable);
        assert_matches!(entry(&doc, "b").value, EntryValue::Unusable);
        assert_matches!(entry(&doc, "c").value, EntryValue::Empty { .. });
        assert_matches!(entry(&doc, "d").value, EntryValue::Text { .. });
    }

    #[test]
    fn test_null_sections_are_absent_not_malformed() {
        let doc = document("catalog:\ncatalogs:\n  legacy:\n");
        assert!(doc.entries.is_empty());
        assert_eq!(doc.defect, None);
    }

    #[test]
    fn test_wrong_shaped_sections_are_malformed_with_no_entries() {
        for content in [
            "catalog: nope\n",
            "catalog:\n  - a\n",
            "catalogs: nope\n",
            "catalogs:\n  - a\n",
            "catalogs:\n  legacy: nope\n",
            "catalog:\n  react: ^1.0.0\ncatalogs:\n  legacy:\n    - a\n",
        ] {
            let doc = document(content);
            assert_eq!(doc.defect, Some(ConfigDefect::Malformed), "{content}");
            assert!(doc.entries.is_empty(), "{content}");
        }
    }

    #[test]
    fn test_duplicate_default_keeps_entries_and_anchors_on_catalogs_default_key() {
        let content = "catalog:\n  react: ^18.0.0\ncatalogs:\n  default:\n    vue: ^3.0.0\n";
        let doc = document(content);
        assert_eq!(doc.defect, Some(ConfigDefect::DuplicateDefaultCatalog));
        assert_eq!(doc.entries.len(), 2);
        let key = doc.duplicate_default_key.expect("key range");
        assert_eq!(text_at(content, key), "default");
        assert_eq!(key.start.line, 3);
    }

    #[test]
    fn test_invalid_yaml_is_an_error_not_a_panic() {
        assert!(parse_workspace_document("catalog: [unclosed\n").is_err());
        assert!(parse_workspace_document("catalog:\n  react: 'unterminated\n").is_err());
    }

    #[test]
    fn test_empty_and_unrelated_documents_are_silent() {
        for content in ["", "# only a comment\n", "packages:\n  - a\n"] {
            let doc = document(content);
            assert!(doc.entries.is_empty());
            assert_eq!(doc.defect, None);
        }
    }

    #[test]
    fn test_alias_value_resolves_text_and_anchors_on_alias_token() {
        let content = "catalog:\n  react: &r ^18.0.0\n  preact: *r\n";
        let doc = document(content);
        assert_eq!(
            version_text(content, &doc, "react").as_deref(),
            Some("^18.0.0")
        );
        let EntryValue::Text { text, range } = &entry(&doc, "preact").value else {
            panic!("alias must resolve");
        };
        assert_eq!(text, "^18.0.0");
        assert_eq!(text_at(content, range.unwrap()), "*r");
    }

    #[test]
    fn test_alias_in_flow_mapping_stops_at_flow_indicator() {
        let content = "catalog: {react: &r ^18.0.0, preact: *r}\n";
        let doc = document(content);
        let EntryValue::Text { range, .. } = &entry(&doc, "preact").value else {
            panic!("alias must resolve");
        };
        assert_eq!(text_at(content, range.unwrap()), "*r");
    }

    #[test]
    fn test_alias_to_unknown_anchor_is_a_syntax_error() {
        assert!(parse_workspace_document("catalog:\n  react: *missing\n").is_err());
    }

    #[test]
    fn test_anchor_defining_scalar_range_excludes_the_anchor() {
        let content = "catalog:\n  react: &r \"^18.0.0\"\n  vue: &v ^3.0.0\n";
        let doc = document(content);
        assert_eq!(
            version_text(content, &doc, "react").as_deref(),
            Some("^18.0.0")
        );
        assert_eq!(
            version_text(content, &doc, "vue").as_deref(),
            Some("^3.0.0")
        );
    }

    #[test]
    fn test_block_scalar_anchors_on_its_indicator_token() {
        let content = "catalog:\n  react: |\n    ^18.0.0\n  semver: >-\n    ^5.0.0\n";
        let doc = document(content);
        let EntryValue::Text { text, range } = &entry(&doc, "react").value else {
            panic!("block scalar keeps its text");
        };
        assert_eq!(text, "^18.0.0");
        assert_eq!(text_at(content, range.unwrap()), "|");
        assert_eq!(version_text(content, &doc, "semver").as_deref(), Some(">-"));
    }

    #[test]
    fn test_escaped_quoted_scalar_has_no_range() {
        let doc = document("catalog:\n  react: \"\\x31\"\n");
        let EntryValue::Text { text, range } = &doc.entries[0].value else {
            panic!("escaped scalar keeps its text");
        };
        assert_eq!(text, "1");
        assert_eq!(*range, None);
    }

    #[test]
    fn test_str_tagged_scalar_is_usable_non_str_tag_is_not() {
        let doc = document("catalog:\n  a: !!str true\n  b: !!int 5\n");
        assert_matches!(entry(&doc, "a").value, EntryValue::Text { .. });
        assert_matches!(entry(&doc, "b").value, EntryValue::Unusable);
    }

    #[test]
    fn test_alias_as_section_value_to_a_mapping_is_malformed() {
        let doc = document("shared: &s\n  react: ^1.0.0\ncatalog: *s\n");
        assert_eq!(doc.defect, Some(ConfigDefect::Malformed));
    }

    #[test]
    fn test_complex_key_does_not_desync_the_section() {
        let content = "catalog:\n  ? [a, b]\n  : x\n  react: ^1.0.0\n";
        let doc = document(content);
        assert_eq!(
            version_text(content, &doc, "react").as_deref(),
            Some("^1.0.0")
        );
    }

    #[test]
    fn test_manifest_entries_become_catalog_entry_dependencies() {
        let content = "catalog:\n  react: ^16.0.0\ncatalogs:\n  legacy:\n    left-pad: ^1.0.0\n";
        let result = manifest(content);
        assert_eq!(result.dependencies.len(), 2);
        let react = &result.dependencies[0];
        assert_eq!(react.name, "react");
        assert_eq!(react.version_req, Some("^16.0.0".into()));
        assert_eq!(text_at(content, react.version_range.unwrap()), "^16.0.0");
        assert_matches!(
            &react.origin,
            NpmDependencyOrigin::CatalogEntry {
                id: CatalogId::Default,
                site: CatalogSite::TopLevelCatalog
            }
        );
        assert_matches!(
            &result.dependencies[1].origin,
            NpmDependencyOrigin::CatalogEntry {
                id: CatalogId::Named(_),
                site: CatalogSite::CatalogsNamed
            }
        );
        assert_eq!(result.duplicate_default_catalog, None);
    }

    #[test]
    fn test_manifest_non_registry_specifiers_are_classified_not_treated_as_registry() {
        let content =
            "catalog:\n  a: npm:preact@^10\n  b: file:../b\n  c: github:o/r\n  d: ^1.0.0\n";
        let result = manifest(content);
        let by_name = |n: &str| result.dependencies.iter().find(|d| d.name == n).unwrap();
        assert_eq!(
            by_name("a").package.as_ref().map(|p| p.as_str()),
            Some("preact")
        );
        assert_matches!(
            by_name("b").source,
            deps_core::parser::DependencySource::Path { .. }
        );
        assert_matches!(
            by_name("c").source,
            deps_core::parser::DependencySource::Git { .. }
        );
        assert_matches!(
            by_name("d").source,
            deps_core::parser::DependencySource::Registry
        );
    }

    #[test]
    fn test_manifest_duplicate_default_reports_key_range() {
        let content = "catalog:\n  react: ^18.0.0\ncatalogs:\n  default:\n    vue: ^3.0.0\n";
        let result = manifest(content);
        assert_eq!(result.dependencies.len(), 2);
        assert!(result.duplicate_default_catalog.is_some());
    }

    #[test]
    fn test_manifest_invalid_yaml_is_an_error() {
        assert!(
            parse_pnpm_workspace_manifest("catalog: [", &uri(), &NpmParseContext::default())
                .is_err()
        );
    }

    #[test]
    fn test_manifest_non_file_uri_still_parses_from_supplied_text() {
        let uri = Url::parse("untitled:pnpm-workspace.yaml").unwrap();
        let result = parse_pnpm_workspace_manifest(
            "catalog:\n  react: ^18.0.0\n",
            &uri,
            &NpmParseContext::default(),
        )
        .unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_manifest_dependency_cap_truncates_with_notice() {
        let mut content = String::from("catalog:\n");
        for i in 0..=deps_core::MAX_DEPENDENCIES_PER_DOCUMENT {
            content.push_str(&format!("  p{i}: ^1.0.0\n"));
        }
        let result = manifest(&content);
        assert_eq!(
            result.dependencies.len(),
            deps_core::MAX_DEPENDENCIES_PER_DOCUMENT
        );
        assert_eq!(
            result.dependency_truncation,
            Some((
                deps_core::MAX_DEPENDENCIES_PER_DOCUMENT,
                deps_core::MAX_DEPENDENCIES_PER_DOCUMENT + 1
            ))
        );
    }

    #[test]
    fn test_empty_entry_is_positioned_right_after_the_colon_and_spaces() {
        let content = "catalog:\n  lodash: \n  \"vue\":\n  react: ^1.0.0\n";
        let doc = document(content);
        let EntryValue::Empty { at } = entry(&doc, "lodash").value else {
            panic!("empty value must be completable");
        };
        assert_eq!((at.start.line, at.start.character), (1, 10));
        assert_eq!(at.start, at.end);
        let EntryValue::Empty { at } = entry(&doc, "vue").value else {
            panic!("quoted key with empty value must be completable");
        };
        assert_eq!((at.start.line, at.start.character), (2, 8));
        assert_matches!(entry(&doc, "react").value, EntryValue::Text { .. });
    }

    #[test]
    fn test_empty_entry_in_a_flow_mapping() {
        let content = String::from("catalog: {lodash:") + " }\n";
        let doc = document(&content);
        let EntryValue::Empty { at } = entry(&doc, "lodash").value else {
            panic!("flow empty value must be completable");
        };
        assert_eq!((at.start.line, at.start.character), (0, 18));
    }

    #[test]
    fn test_empty_entry_is_a_dependency_with_no_requirement_and_a_completion_range() {
        let content = "catalog:\n  lodash: \n";
        let result = manifest(content);
        assert_eq!(result.dependencies.len(), 1);
        let lodash = &result.dependencies[0];
        assert_eq!(lodash.name, "lodash");
        assert_eq!(lodash.version_req, None);
        let range = lodash.version_range.expect("completion position");
        assert_eq!((range.start.line, range.start.character), (1, 10));
    }

    #[test]
    fn test_duplicate_keys_are_malformed() {
        for content in [
            "catalog:\n  react: ^1.0.0\n  react: ^2.0.0\n",
            "catalog:\n  react: ^1.0.0\ncatalog:\n  vue: ^3.0.0\n",
            "packages:\n  - a\npackages:\n  - b\n",
            "catalogs:\n  legacy:\n    react: ^1.0.0\n  legacy:\n    vue: ^3.0.0\n",
        ] {
            let doc = document(content);
            assert_eq!(doc.defect, Some(ConfigDefect::Malformed), "{content}");
            assert!(doc.entries.is_empty(), "{content}");
        }
    }

    #[test]
    fn test_same_key_in_different_mappings_is_not_a_duplicate() {
        let doc = document("catalog:\n  react: ^1.0.0\ncatalogs:\n  legacy:\n    react: ^0.9.0\n");
        assert_eq!(doc.defect, None);
        assert_eq!(doc.entries.len(), 2);
    }

    #[test]
    fn test_alias_bomb_is_rejected_by_the_expansion_bound() {
        let mut bomb = String::from("a: &a [x, x, x, x, x, x, x, x, x]\n");
        for i in 0..14 {
            let prev = if i == 0 {
                "a".to_string()
            } else {
                format!("l{}", i - 1)
            };
            let refs = std::iter::repeat_n(format!("*{prev}"), 9)
                .collect::<Vec<_>>()
                .join(", ");
            bomb.push_str(&format!("l{i}: &l{i} [{refs}]\n"));
        }
        bomb.push_str("catalog:\n  react: ^1.0.0\n");
        assert!(parse_workspace_document(&bomb).is_err());
    }

    #[test]
    fn test_anchors_beyond_the_table_bound_leave_later_aliases_unusable() {
        let mut content = String::from("catalog:\n");
        for i in 0..=MAX_ANCHORS {
            content.push_str(&format!("  p{i}: &a{i} ^1.0.0\n"));
        }
        content.push_str("  alias: *a4096\n");
        let doc = document(&content);
        assert_matches!(entry(&doc, "alias").value, EntryValue::Unusable);
        assert_matches!(entry(&doc, "p0").value, EntryValue::Text { .. });
    }

    #[test]
    fn test_alias_to_an_anchored_scalar_over_the_length_cap_is_unusable() {
        let long = "1".repeat(MAX_ANCHORED_SCALAR_CHARS + 1);
        let content = format!("catalog:\n  big: &b {long}\n  alias: *b\n");
        let doc = document(&content);
        assert_matches!(entry(&doc, "big").value, EntryValue::Text { .. });
        assert_matches!(entry(&doc, "alias").value, EntryValue::Unusable);
    }

    #[test]
    fn test_seven_megabyte_file_of_entries_is_rejected_by_the_expansion_bound() {
        let mut content = String::from("catalog:\n");
        let mut i = 0usize;
        while content.len() < 7 * 1024 * 1024 {
            content.push_str(&format!("  p{i}: ^1.0.0\n"));
            i += 1;
        }
        assert!(parse_workspace_document(&content).is_err());
    }

    #[test]
    fn test_seven_megabyte_file_of_padding_still_parses() {
        let mut content = String::from("catalog:\n  react: ^18.0.0\n");
        while content.len() < 7 * 1024 * 1024 {
            content.push_str("# padding padding padding padding padding padding padding\n");
        }
        assert_eq!(manifest(&content).dependencies.len(), 1);
    }

    #[test]
    fn test_deep_nesting_is_rejected() {
        let deep = format!("catalog:\n  react: {}\n", "[".repeat(10_000));
        assert!(parse_workspace_document(&deep).is_err());
    }

    #[test]
    fn test_oversized_requirement_is_kept_for_the_length_capped_pipeline() {
        let long = "^1.0.0 || ".repeat(deps_core::lsp_helpers::MAX_REQUIREMENT_LEN);
        let content = format!("catalog:\n  react: \"{long}1.0.0\"\n");
        let doc = document(&content);
        assert_matches!(doc.entries[0].value, EntryValue::Text { .. });
    }

    fn override_deps(result: &NpmParseResult) -> Vec<&NpmDependency> {
        result
            .dependencies
            .iter()
            .filter(|dep| matches!(dep.origin, NpmDependencyOrigin::Override { .. }))
            .collect()
    }

    #[test]
    fn test_override_entries_become_dependencies_positioned_on_the_value() {
        let content = "overrides:\n  lodash: ^4.17.0\n  \"foo@<2\": 2.0.0\n  \"@s/pkg\": 'npm:other@^1.2.0'\n";
        let result = manifest(content);
        let deps = override_deps(&result);
        assert_eq!(deps.len(), 3);

        assert_eq!(deps[0].name, "lodash");
        assert_eq!(text_at(content, deps[0].version_range.unwrap()), "^4.17.0");

        assert_eq!(deps[1].name, "foo");
        let NpmDependencyOrigin::Override { selector } = &deps[1].origin else {
            panic!("override origin expected");
        };
        assert_eq!(selector.target_selector().unwrap().as_str(), "<2");
        assert_eq!(text_at(content, deps[1].version_range.unwrap()), "2.0.0");

        assert_eq!(deps[2].name, "@s/pkg");
        assert_eq!(deps[2].package.as_ref().unwrap(), "other");
    }

    #[test]
    fn test_override_values_without_a_range_are_skipped() {
        let content = "overrides:\n  a: \"-\"\n  b: $b\n  c: \"catalog:\"\n  d: ^1.0.0\n  e: ~\n  f:\n    nested: 1\n";
        let result = manifest(content);
        let names: Vec<_> = override_deps(&result)
            .iter()
            .map(|dep| dep.name.as_str().to_string())
            .collect();
        assert_eq!(names, ["d"]);
    }

    #[test]
    fn test_override_key_with_parent_chain_targets_the_last_segment() {
        let content = "overrides:\n  \"bar@1>foo@2\": ^3.0.0\n  \"bad>\": ^1.0.0\n  \"\": ^1.0.0\n";
        let result = manifest(content);
        let deps = override_deps(&result);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "foo");
        let NpmDependencyOrigin::Override { selector } = &deps[0].origin else {
            panic!("override origin expected");
        };
        assert_eq!(selector.parents().len(), 1);
        assert_eq!(selector.parents()[0], "bar");
    }

    #[test]
    fn test_wrong_shaped_overrides_drop_only_that_section() {
        for content in [
            "catalog:\n  react: ^18.0.0\noverrides:\n  - a\n  - b\n",
            "catalog:\n  react: ^18.0.0\noverrides: nope\n",
            "catalog:\n  react: ^18.0.0\noverrides:\n  a: ^1.0.0\n  a: ^2.0.0\n",
        ] {
            let doc = document(content);
            assert!(doc.defect.is_none(), "{content}");
            assert!(doc.overrides.is_empty(), "{content}");
            let result = manifest(content);
            assert_eq!(result.dependencies.len(), 1, "{content}");
            assert_matches!(
                result.dependencies[0].origin,
                NpmDependencyOrigin::CatalogEntry { .. }
            );
        }
    }

    #[test]
    fn test_overrides_never_reach_catalog_resolution() {
        let content = "catalog:\n  react: ^18.0.0\noverrides:\n  react: ^17.0.0\n";
        let doc = document(content);
        assert_eq!(doc.entries.len(), 1);
        assert_eq!(doc.overrides.len(), 1);
        assert_matches!(&doc.entries[0].value, EntryValue::Text { text, .. } if text == "^18.0.0");
    }

    #[test]
    fn test_override_alias_value_is_positioned_on_the_alias_token() {
        let content = "overrides:\n  a: &v ^1.0.0\n  b: *v\n";
        let doc = document(content);
        let EntryValue::Text { text, range } = &doc.overrides[1].value else {
            panic!("alias text expected");
        };
        assert_eq!(text, "^1.0.0");
        assert_eq!(text_at(content, range.unwrap()), "*v");
    }

    fn globs(content: &str) -> Option<Vec<PackageGlob>> {
        document(content).package_globs
    }

    #[test]
    fn test_packages_globs_are_parsed_with_negation() {
        let parsed = globs("packages:\n  - 'apps/*'\n  - \"!**/test/**\"\n  - ./libs/\n").unwrap();
        assert_eq!(parsed.len(), 3);
        assert_matches!(&parsed[0], PackageGlob::Include(g) if g.as_str() == "apps/*");
        assert_matches!(&parsed[1], PackageGlob::Exclude(g) if g.as_str() == "**/test/**");
        assert_matches!(&parsed[2], PackageGlob::Include(g) if g.as_str() == "libs");
    }

    #[test]
    fn test_hostile_packages_globs_are_dropped_at_parse_time() {
        let parsed = globs("packages:\n  - ../outside\n  - /abs\n  - 'a\\b'\n  - ok/*\n").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_matches!(&parsed[0], PackageGlob::Include(g) if g.as_str() == "ok/*");
    }

    #[test]
    fn test_absent_or_wrong_shaped_packages_fall_back_to_the_pnpm_default() {
        for content in [
            "catalog:\n  a: 1.0.0\n",
            "packages: nope\n",
            "packages:\n  nested: 1\n",
            "packages:\n  - [a, b]\n",
            "packages:\n",
        ] {
            assert!(globs(content).is_none(), "{content}");
            let members = manifest(content).workspace_members.unwrap();
            assert_eq!(members.globs(), PackageGlob::defaults(), "{content}");
        }
    }

    #[test]
    fn test_empty_packages_list_selects_no_members() {
        let result = manifest("packages: []\n");
        assert!(result.workspace_members.unwrap().globs().is_empty());
    }

    #[test]
    fn test_workspace_members_are_rooted_at_the_workspace_file_directory() {
        let result = manifest("packages:\n  - apps/*\n");
        let members = result.workspace_members.unwrap();
        assert_eq!(members.root(), std::path::Path::new("/repo"));
    }

    #[test]
    fn test_packages_cap_bounds_the_number_of_globs() {
        let mut content = String::from("packages:\n");
        for i in 0..(MAX_PACKAGE_GLOBS + 50) {
            content.push_str(&format!("  - p{i}/*\n"));
        }
        assert_eq!(globs(&content).unwrap().len(), MAX_PACKAGE_GLOBS);
        assert!(document(&content).package_globs_truncated);
        assert!(
            manifest(&content)
                .workspace_members
                .unwrap()
                .globs_truncated()
        );
    }
}
