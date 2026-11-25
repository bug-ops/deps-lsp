//! On-disk entry format for the persisted registry cache (spec 051).
//!
//! Layout: magic `DEPSLSPC`, `u16` little-endian version, `u32`
//! little-endian header length (at most 64 KiB), a JSON [`Header`], then the
//! body. The header carries the key (URL and `Accept`), the validators, the
//! body length and an FNV-1a 64 checksum ([`crate::hash::fnv1a64`]), so a file is
//! self-describing and a damaged or foreign one is rejected instead of trusted. Decoding is total:
//! every malformed input maps to a [`DecodeError`], never a panic.

use super::key::PersistKey;
use crate::cache::MAX_CACHEABLE_ENTRY_BYTES;
use crate::hash::fnv1a64;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

const MAGIC: &[u8; 8] = b"DEPSLSPC";
const FORMAT_VERSION: u16 = 1;
const MAX_HEADER_LEN: usize = 64 * 1024;

/// Why a persisted entry was rejected.
#[derive(Debug, thiserror::Error)]
pub(super) enum DecodeError {
    /// The file does not start with the entry magic.
    #[error("not a persisted cache entry")]
    BadMagic,
    /// The file was written by a different format version.
    #[error("unsupported entry format version")]
    ForeignVersion,
    /// The declared header length exceeds the 64 KiB cap.
    #[error("entry header exceeds the size cap")]
    HeaderTooLarge,
    /// The file ends before the prefix, header or body is complete.
    #[error("entry is truncated")]
    Truncated,
    /// The header is not valid JSON of the expected shape.
    #[error("entry header is malformed: {0}")]
    Header(#[source] serde_json::Error),
    /// The body does not match the recorded checksum.
    #[error("entry body failed its checksum")]
    Checksum,
    /// The entry belongs to a different URL than requested.
    #[error("entry URL does not match the request")]
    UrlMismatch,
    /// The entry belongs to a different `Accept` value than requested.
    #[error("entry Accept does not match the request")]
    AcceptMismatch,
    /// The declared body length exceeds the cacheable cap.
    #[error("entry body exceeds the cacheable size cap")]
    Oversized,
    /// Reading the underlying source failed.
    #[error("reading the entry failed: {0}")]
    Io(#[source] io::Error),
}

/// Why an entry cannot be built: it could never be decoded again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum EncodeError {
    /// The serialized header would exceed the 64 KiB cap.
    #[error("entry header exceeds the size cap")]
    HeaderTooLarge,
    /// The body exceeds the cacheable cap.
    #[error("entry body exceeds the cacheable size cap")]
    Oversized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    url: String,
    accept: String,
    etag: Option<String>,
    last_modified: Option<String>,
    link: Option<String>,
    body_len: u64,
    body_fnv1a64: u64,
}

/// The validator and pagination headers stored alongside a body.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct StoredHeaders<'a> {
    pub(super) etag: Option<&'a str>,
    pub(super) last_modified: Option<&'a str>,
    pub(super) link: Option<&'a str>,
}

/// A cache entry in its persisted form: key, validators and body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PersistedEntry {
    header: Header,
    body: Vec<u8>,
}

impl PersistedEntry {
    /// Builds an entry, recording the body length and checksum.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::Oversized`] when `body` exceeds the cacheable cap and
    /// [`EncodeError::HeaderTooLarge`] when the serialized header would exceed the 64 KiB cap,
    /// so every entry that exists can be decoded again.
    pub(super) fn new(
        key: &PersistKey,
        headers: StoredHeaders<'_>,
        body: Vec<u8>,
    ) -> Result<Self, EncodeError> {
        if body.len() > MAX_CACHEABLE_ENTRY_BYTES {
            return Err(EncodeError::Oversized);
        }
        let body_len = u64::try_from(body.len()).map_err(|_| EncodeError::Oversized)?;
        let header = Header {
            url: key.url().to_owned(),
            accept: key.accept().to_owned(),
            etag: headers.etag.map(str::to_owned),
            last_modified: headers.last_modified.map(str::to_owned),
            link: headers.link.map(str::to_owned),
            body_len,
            body_fnv1a64: fnv1a64(&body),
        };
        if serialize_header(&header).len() > MAX_HEADER_LEN {
            return Err(EncodeError::HeaderTooLarge);
        }
        Ok(Self { header, body })
    }

    /// Serializes the entry into the on-disk layout.
    ///
    /// [`Self::new`] guarantees the header and body fit their caps, so the output always decodes.
    #[must_use]
    pub(super) fn encode(&self) -> Vec<u8> {
        let header = serialize_header(&self.header);
        #[expect(
            clippy::expect_used,
            reason = "Self::new bounds the header at MAX_HEADER_LEN, far below u32::MAX"
        )]
        let header_len = u32::try_from(header.len()).expect("header length fits u32");
        let mut out = Vec::with_capacity(PREFIX_LEN + header.len() + self.body.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&header_len.to_le_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.body);
        out
    }

    /// Parses and fully validates a persisted entry.
    ///
    /// Age is classified separately from the file time.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] for a wrong magic or version, an oversized
    /// or malformed header, a URL or `Accept` that differs from the expected
    /// ones, a declared body over the cacheable cap (never truncated), a
    /// short file, or a checksum mismatch.
    pub(super) fn decode(bytes: &[u8], key: &PersistKey) -> Result<Self, DecodeError> {
        let mut reader = bytes;
        let header = read_header(&mut reader)?;
        if header.url != key.url() {
            return Err(DecodeError::UrlMismatch);
        }
        if header.accept != key.accept() {
            return Err(DecodeError::AcceptMismatch);
        }
        let body_len = usize::try_from(header.body_len)
            .ok()
            .filter(|len| *len <= MAX_CACHEABLE_ENTRY_BYTES)
            .ok_or(DecodeError::Oversized)?;
        let (body, _) = reader
            .split_at_checked(body_len)
            .ok_or(DecodeError::Truncated)?;
        if fnv1a64(body) != header.body_fnv1a64 {
            return Err(DecodeError::Checksum);
        }
        Ok(Self {
            header,
            body: body.to_vec(),
        })
    }

    /// The header-only identity of this entry.
    #[must_use]
    pub(super) fn fingerprint(&self) -> EntryFingerprint {
        EntryFingerprint(self.header.clone())
    }

    /// The cached response body.
    #[must_use]
    pub(super) fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Header-only identity of an entry: key, validators, body length and checksum.
///
/// Lets a restamp confirm a file still holds the entry it was decided on
/// without reading the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EntryFingerprint(Header);

impl EntryFingerprint {
    /// Reads the fingerprint from the start of an entry file.
    ///
    /// Consumes at most the 14-byte prefix plus 64 KiB of header and never
    /// touches the body.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] for a wrong magic or version, an oversized,
    /// short or malformed header, or an I/O failure.
    pub(super) fn from_reader<R: Read>(mut reader: R) -> Result<Self, DecodeError> {
        read_header(&mut reader).map(Self)
    }

    /// The recorded body length in bytes.
    #[must_use]
    pub(super) const fn body_len(&self) -> u64 {
        self.0.body_len
    }

    /// The recorded FNV-1a 64 checksum of the body.
    #[must_use]
    pub(super) const fn body_fnv1a64(&self) -> u64 {
        self.0.body_fnv1a64
    }
}

fn serialize_header(header: &Header) -> Vec<u8> {
    #[expect(
        clippy::expect_used,
        reason = "Header holds only strings and integers, which always serialize"
    )]
    serde_json::to_vec(header).expect("header serializes")
}

const PREFIX_LEN: usize = MAGIC.len() + size_of::<u16>() + size_of::<u32>();

fn read_array<R: Read, const N: usize>(reader: &mut R) -> Result<[u8; N], DecodeError> {
    let mut buf = [0u8; N];
    reader.read_exact(&mut buf).map_err(io_error)?;
    Ok(buf)
}

fn io_error(error: io::Error) -> DecodeError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        DecodeError::Truncated
    } else {
        DecodeError::Io(error)
    }
}

fn read_header<R: Read>(reader: &mut R) -> Result<Header, DecodeError> {
    let prefix: [u8; PREFIX_LEN] = read_array(reader)?;
    let (magic, rest) = prefix.split_at(MAGIC.len());
    if magic != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let (version, header_len) = rest.split_at(size_of::<u16>());
    if version != FORMAT_VERSION.to_le_bytes() {
        return Err(DecodeError::ForeignVersion);
    }
    let header_len = header_len
        .as_array()
        .copied()
        .map(u32::from_le_bytes)
        .and_then(|len| usize::try_from(len).ok())
        .filter(|len| *len <= MAX_HEADER_LEN)
        .ok_or(DecodeError::HeaderTooLarge)?;
    let mut header = vec![0u8; header_len];
    reader.read_exact(&mut header).map_err(io_error)?;
    serde_json::from_slice(&header).map_err(DecodeError::Header)
}
