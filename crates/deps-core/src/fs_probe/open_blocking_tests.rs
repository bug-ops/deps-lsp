//! #2156.6: `OpenBlocking` replaces the raw `i32` open-flag parameter. Its flag mapping is the
//! only behavior; the FIFO regression lives in `tests/fs_probe_persist.rs`.

#![cfg(unix)]

use super::OpenBlocking;

#[test]
fn open_blocking_allow_adds_no_flags() {
    assert_eq!(OpenBlocking::Allow.flags(), 0);
}

#[test]
fn open_blocking_non_blocking_sets_o_nonblock() {
    assert_eq!(OpenBlocking::NonBlocking.flags(), libc::O_NONBLOCK);
}
