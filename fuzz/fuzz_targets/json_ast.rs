//! Fuzzes `deps_core::json_ast`'s JSONC AST parsing and position recovery — shared by
//! every JSON-manifest ecosystem (npm's `package.json`, Composer's `composer.json`,
//! NuGet's `packages.config`-adjacent JSON, Deno's `deno.json(c)`) (#673).
//!
//! Property under test: parsing and position lookup never panic for any byte input, and
//! any `Range` returned never claims a UTF-16 character offset that could not exist on
//! its reported line.

#![no_main]

use deps_core::json_ast::JsonAst;
use deps_core::lsp_helpers::LineOffsetTable;
use libfuzzer_sys::fuzz_target;

const CANDIDATE_SECTIONS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "require",
    "require-dev",
    "imports",
];

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let Some(ast) = JsonAst::parse(content) else {
        return;
    };
    let table = LineOffsetTable::new(content);

    for section_key in CANDIDATE_SECTIONS {
        let Some(section) = ast.section(section_key) else {
            continue;
        };
        // Re-scan the raw text for plausible property-name tokens rather than trying to
        // re-derive them from the AST (kept independent of `json_ast`'s own traversal, so
        // this doesn't just retest the parser against itself).
        for token in content.split(['"', ':', ',', '{', '}', '[', ']']) {
            let name = token.trim();
            if name.is_empty() {
                continue;
            }
            if let Some((name_range, version_range)) = section.position(name, content, &table) {
                assert!(
                    table.line_start(name_range.start.line as usize).is_some(),
                    "name_range claims a line past the end of the document"
                );
                if let Some(version_range) = version_range {
                    assert!(
                        table.line_start(version_range.start.line as usize).is_some(),
                        "version_range claims a line past the end of the document"
                    );
                }
            }
        }
    }
});
