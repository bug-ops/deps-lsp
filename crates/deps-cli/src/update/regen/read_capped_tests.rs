//! #2155: one `read_capped` owns the cap boundary rule for both child-output runners: output of
//! exactly `cap` bytes is complete, one byte more is over the cap.

use super::run::{Capped, read_capped};

const CAP: u64 = 16;

async fn read(len: u64) -> (Capped, usize) {
    let data = vec![b'x'; usize::try_from(len).expect("small")];
    let mut reader = data.as_slice();
    let capped = read_capped(&mut reader, CAP).await.expect("in-memory read");
    (capped, reader.len())
}

#[tokio::test]
async fn read_capped_below_the_cap_is_complete() {
    let (capped, unread) = read(CAP - 1).await;
    assert_eq!(capped, Capped::Complete(vec![b'x'; 15]));
    assert_eq!(unread, 0);
}

#[tokio::test]
async fn read_capped_of_exactly_the_cap_is_complete() {
    let (capped, unread) = read(CAP).await;
    assert_eq!(capped, Capped::Complete(vec![b'x'; 16]));
    assert_eq!(unread, 0);
}

#[tokio::test]
async fn read_capped_one_byte_over_the_cap_is_over_cap_with_the_first_cap_bytes() {
    let (capped, unread) = read(CAP + 1).await;
    assert_eq!(capped, Capped::OverCap(vec![b'x'; 16]));
    assert_eq!(unread, 0);
}

#[tokio::test]
async fn read_capped_far_over_the_cap_stops_one_byte_past_it() {
    let (capped, unread) = read(3 * CAP).await;
    assert_eq!(capped, Capped::OverCap(vec![b'x'; 16]));
    assert_eq!(unread, usize::try_from(3 * CAP - (CAP + 1)).expect("small"));
}

#[tokio::test]
async fn read_capped_of_empty_input_is_complete_and_empty() {
    let (capped, _) = read(0).await;
    assert_eq!(capped, Capped::Complete(Vec::new()));
}

#[tokio::test]
async fn read_capped_with_a_zero_cap_distinguishes_empty_from_any_output() {
    let mut empty: &[u8] = b"";
    assert_eq!(
        read_capped(&mut empty, 0).await.expect("read"),
        Capped::Complete(Vec::new())
    );
    let mut one: &[u8] = b"x";
    assert_eq!(
        read_capped(&mut one, 0).await.expect("read"),
        Capped::OverCap(Vec::new())
    );
}
