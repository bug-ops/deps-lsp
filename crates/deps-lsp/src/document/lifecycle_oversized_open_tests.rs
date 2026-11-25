//! A rejected (oversized) `didOpen` must not release the reservation of a valid open of the same
//! URI that is still in flight: reserving before validation let the rejected open replace and
//! then remove that reservation, so the valid open found none and never inserted its document.
//!
//! Declared from `lifecycle.rs` as a child module.

#![expect(
    clippy::unwrap_used,
    reason = "test code; clippy's allow-*-in-tests does not see this `cfg(all(test, ..))` module"
)]

use super::*;
use crate::test_utils::test_helpers::create_test_client_and_config;
use deps_core::{DepsError, EcosystemId};
use std::assert_matches;

fn catalog_uri(name: &str) -> Uri {
    let url = deps_core::test_util::test_uri(&format!("/project/gradle/{name}"));
    crate::lsp_types_interop::to_lsp_uri(&url)
}

fn document() -> DocumentState {
    DocumentState::new_without_parse_result(EcosystemId::Gradle, "[versions]\n".to_owned())
}

async fn oversized_open(state: &Arc<ServerState>, uri: &Uri) -> Result<Option<CommittedChange>> {
    let (client, config) = create_test_client_and_config();
    let oversized = "x".repeat(usize::try_from(MAX_FILE_SIZE).unwrap() + 1);
    open_document(
        uri.clone(),
        oversized,
        Some(2),
        Arc::clone(state),
        client,
        config,
    )
    .await
}

#[tokio::test]
async fn oversized_open_leaves_the_reservation_of_an_open_in_flight_alone() {
    let state = Arc::new(ServerState::new());
    let uri = catalog_uri("libs.versions.toml");
    let in_flight = state.reserve_open(&uri);
    let epoch = state.capture_open_epoch(&uri).unwrap();

    let result = oversized_open(&state, &uri).await;

    assert_matches!(
        result,
        Err(DepsError::Io(ref error)) if error.kind() == std::io::ErrorKind::FileTooLarge
    );
    assert_eq!(state.capture_open_epoch(&uri), Some(epoch));
    assert!(state.insert_opened(in_flight, document()));
    assert!(state.get_document(&uri).is_some());
}

#[tokio::test]
async fn oversized_open_of_an_unsupported_file_is_reported_as_unsupported() {
    let state = Arc::new(ServerState::new());
    let uri = catalog_uri("notes.txt");

    let result = oversized_open(&state, &uri).await;

    assert_matches!(result, Err(DepsError::UnsupportedEcosystem(_)));
    assert!(state.capture_open_epoch(&uri).is_none());
}
