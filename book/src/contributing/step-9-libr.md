# Step 9: Create lib.rs

Expose public API in `lib.rs`:

```rust
//! {Ecosystem} support for deps-lsp.

pub mod ecosystem;
pub mod error;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;

pub use ecosystem::{Ecosystem}Ecosystem;
pub use parser::parse_{manifest};
pub use registry::{Ecosystem}Registry;
pub use types::{{Ecosystem}Dependency, {Ecosystem}Version};
```

