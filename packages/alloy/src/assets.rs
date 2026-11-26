//! The asset pipeline: carrying real bytes through a UTF-8 deploy channel.
//!
//! # The constraint
//!
//! `deploy_source` admits a JSON string-valued, UTF-8-only file map, so a
//! binary cannot make the hop. Applications work around this four different ways
//! today, and the most expensive of them forces every image and font to
//! become a data URI — which took one app's first-paint graph from 7.09 MiB
//! to 11.29 MiB, because the browser then downloads base64 instead of bytes.
//!
//! # The answer
//!
//! `alloy-gen` packs the built frontend into one archive, compresses it, and
//! base64s it into `src/generated/assets.rs` as ordinary string constants.
//! On boot the app decodes the archive and seeds the blob plane, and the
//! gateway then serves **real bytes** from the content face. The 4/3 encoding
//! penalty is paid once in the repository and never by a browser.
//!
//! # Bounds
//!
//! Every decoder here is fed by committed source, but a decoder that can
//! panic or allocate without limit on malformed input is a liability in a
//! process with a hard `memory.max`. So each one is total: it returns
//! [`AlloyError`] rather than panicking, validates every offset and length
//! before use, and refuses an archive that would exceed [`MAX_ARCHIVE_BYTES`].

use std::collections::BTreeMap;

use ferrite_app::client::BlobClusterClient;
use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::tracing;

use crate::alloy::error::{AlloyError, Result};

/// The largest archive the decoder will produce. The platform's object cap is
/// 16 MiB and the source-admission bound is smaller still, so an archive
/// claiming more than this is malformed rather than merely large.
pub const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

/// The shortest run worth encoding as a back-reference.
const MIN_MATCH: usize = 3;

/// The longest run one back-reference can carry.
const MAX_MATCH: usize = MIN_MATCH + 255;

/// The look-behind window: a 16-bit distance.
const WINDOW: usize = 65_535;

/// One file in the packed archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetFile {
    /// The path as served, relative to the asset root.
    pub path: String,
    /// The file's bytes.
    pub bytes: Vec<u8>,
}

/// The digest manifest `alloy-gen` emits beside the archive.
///
/// Blob keys are caller-chosen, so content addressing is a Alloy *convention*:
/// the generator computes each asset's SHA-256 and uses that digest as both
/// the blob key and the URL segment, which is what makes immutable caching
/// sound and makes a redundant seed write a no-op.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct AssetManifest {
    /// Served path → hex SHA-256 digest.
    pub entries: BTreeMap<String, String>,
    /// The build id this manifest belongs to.
    pub build: String,
}

impl AssetManifest {
    /// Build a manifest by digesting each file.
    pub fn of(files: &[AssetFile], build: impl Into<String>) -> Self {
        let mut entries = BTreeMap::new();
        for f in files {
            entries.insert(f.path.clone(), hex_digest(&f.bytes));
        }
        Self {
            entries,
            build: build.into(),
        }
    }

    /// The digest for a served path.
    pub fn digest_of(&self, path: &str) -> Option<&str> {
        self.entries.get(path).map(String::as_str)
    }

    /// The total number of assets.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the manifest names nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The hex SHA-256 of `bytes` — a blob key, a URL segment, and an ETag.
pub fn hex_digest(bytes: &[u8]) -> String {
    ferrite_app::crypto::hex(&ferrite_app::crypto::sha256(bytes))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as standard base64 with padding.
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn b64_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a') as u32 + 26),
        b'0'..=b'9' => Some((c - b'0') as u32 + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode the base64 chunks `alloy-gen` emits as `&[&str]`.
///
/// The generator splits the encoding across many string literals so no single
/// line is unreasonably long; concatenation is part of the format, so the
/// chunk boundaries are not required to align to a 4-character group.
pub fn base64_decode_chunks(chunks: &[&str]) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut padding = 0usize;
    let mut symbols = 0usize;
    for chunk in chunks {
        for &c in chunk.as_bytes() {
            if c == b'\n' || c == b'\r' {
                continue;
            }
            if c == b'=' {
                padding += 1;
                continue;
            }
            if padding > 0 {
                return Err(AlloyError::internal(
                    "the embedded asset archive has base64 data after its padding",
                ));
            }
            let v = b64_val(c).ok_or_else(|| {
                AlloyError::internal("the embedded asset archive is not valid base64")
            })?;
            symbols += 1;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                if out.len() > MAX_ARCHIVE_BYTES {
                    return Err(AlloyError::internal(
                        "the embedded asset archive exceeds the decoder's size bound",
                    ));
                }
            }
        }
    }
    // A decoder that accepts malformed padding silently accepts a corrupted
    // archive, so the frame is validated rather than assumed. Standard
    // base64 encodes in four-symbol groups: at most two padding characters,
    // a total that is a multiple of four, and no set bits left over. The
    // chunk boundaries are a source-formatting detail, so these hold over
    // the CONCATENATION, not over any single chunk.
    if padding > 2 {
        return Err(AlloyError::internal(
            "the embedded asset archive carries more than two padding characters",
        ));
    }
    if (symbols + padding) % 4 != 0 {
        return Err(AlloyError::internal(
            "the embedded asset archive is not a whole number of base64 groups",
        ));
    }
    if bits > 0 && acc & ((1u32 << bits) - 1) != 0 {
        return Err(AlloyError::internal(
            "the embedded asset archive has non-zero bits after its last whole byte",
        ));
    }
    Ok(out)
}

/// Compress with the archive's LZSS variant.
///
/// The format is deliberately small enough to re-implement in the generator
/// and to audit by eye: a control byte carries eight flags, LSB first; a set
/// flag means one literal byte follows, a clear flag means a back-reference
/// of `u16` big-endian distance plus one length byte holding `len - MIN_MATCH`.
pub fn lzss_compress(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() / 2 + 16);
    let mut i = 0usize;
    while i < input.len() {
        let control_at = out.len();
        out.push(0);
        let mut control = 0u8;
        for bit in 0..8 {
            if i >= input.len() {
                break;
            }
            let window_start = i.saturating_sub(WINDOW);
            let mut best_len = 0usize;
            let mut best_dist = 0usize;
            // A bounded greedy search: long enough to compress real bundles,
            // short enough that packing stays linear in practice.
            //
            // The search runs only when there IS history. At offset 0 the
            // candidate cursor would be the cursor itself, so every byte
            // would "match" at distance 0 — a self-reference the decoder
            // rightly refuses as malformed, since it names bytes that do not
            // exist yet.
            let mut j = i.saturating_sub(1);
            let mut probes = 0u32;
            while i > 0 && j >= window_start && probes < 256 {
                probes += 1;
                let max_len = MAX_MATCH.min(input.len() - i);
                let mut len = 0usize;
                while len < max_len && input[j + len] == input[i + len] {
                    len += 1;
                }
                if len > best_len {
                    best_len = len;
                    best_dist = i - j;
                    if len == MAX_MATCH {
                        break;
                    }
                }
                if j == window_start {
                    break;
                }
                j -= 1;
            }
            if best_len >= MIN_MATCH {
                out.extend_from_slice(&(best_dist as u16).to_be_bytes());
                out.push((best_len - MIN_MATCH) as u8);
                i += best_len;
            } else {
                control |= 1 << bit;
                out.push(input[i]);
                i += 1;
            }
        }
        out[control_at] = control;
    }
    out
}

/// Decompress an LZSS stream, bounded by `expected_len`.
///
/// Every back-reference is validated before it is followed: a zero distance,
/// a distance reaching before the start of the output, or a length that would
/// exceed the declared size is a malformed archive, not a panic.
pub fn lzss_decompress(input: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    if expected_len > MAX_ARCHIVE_BYTES {
        return Err(AlloyError::internal(
            "the embedded asset archive declares a size beyond the decoder's bound",
        ));
    }
    let mut out: Vec<u8> = Vec::with_capacity(expected_len.min(1 << 20));
    let mut i = 0usize;
    while i < input.len() {
        let control = input[i];
        i += 1;
        for bit in 0..8 {
            if i >= input.len() {
                break;
            }
            if control & (1 << bit) != 0 {
                out.push(input[i]);
                i += 1;
            } else {
                if i + 3 > input.len() {
                    return Err(AlloyError::internal(
                        "the embedded asset archive ends inside a back-reference",
                    ));
                }
                let dist = u16::from_be_bytes([input[i], input[i + 1]]) as usize;
                let len = input[i + 2] as usize + MIN_MATCH;
                i += 3;
                if dist == 0 || dist > out.len() {
                    return Err(AlloyError::internal(
                        "the embedded asset archive names a back-reference outside its output",
                    ));
                }
                let start = out.len() - dist;
                for k in 0..len {
                    let b = out[start + k];
                    out.push(b);
                }
            }
            if out.len() > expected_len {
                return Err(AlloyError::internal(
                    "the embedded asset archive produced more bytes than it declared",
                ));
            }
        }
    }
    if out.len() != expected_len {
        return Err(AlloyError::internal(format!(
            "the embedded asset archive declared {expected_len} bytes and produced {}",
            out.len()
        )));
    }
    Ok(out)
}

fn read_u32(buf: &[u8], at: usize) -> Result<u32> {
    if at + 4 > buf.len() {
        return Err(AlloyError::internal(
            "the embedded asset archive ends inside a length field",
        ));
    }
    Ok(u32::from_be_bytes([
        buf[at],
        buf[at + 1],
        buf[at + 2],
        buf[at + 3],
    ]))
}

/// Pack files into the archive body: `count`, then `(name, bytes)` records,
/// each length-prefixed with a big-endian `u32`.
pub fn pack_archive(files: &[AssetFile]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&(files.len() as u32).to_be_bytes());
    // Sorted, so the same input tree always produces the same archive and a
    // rebuild is a reviewable no-op rather than a reordered diff.
    let mut sorted: Vec<&AssetFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    for f in sorted {
        out.extend_from_slice(&(f.path.len() as u32).to_be_bytes());
        out.extend_from_slice(f.path.as_bytes());
        out.extend_from_slice(&(f.bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&f.bytes);
    }
    out
}

/// Unpack the archive body.
pub fn unpack_archive(buf: &[u8]) -> Result<Vec<AssetFile>> {
    let count = read_u32(buf, 0)? as usize;
    let mut at = 4usize;
    // A count field cannot be trusted before it is used to reserve: each
    // record costs at least eight bytes, so anything larger is malformed.
    if count > buf.len() / 8 + 1 {
        return Err(AlloyError::internal(
            "the embedded asset archive declares more files than its bytes can hold",
        ));
    }
    let mut files = Vec::with_capacity(count);
    for _ in 0..count {
        let name_len = read_u32(buf, at)? as usize;
        at += 4;
        if at + name_len > buf.len() {
            return Err(AlloyError::internal(
                "the embedded asset archive ends inside a file name",
            ));
        }
        let path = String::from_utf8(buf[at..at + name_len].to_vec())
            .map_err(|_| AlloyError::internal("an asset path is not valid UTF-8"))?;
        at += name_len;
        let data_len = read_u32(buf, at)? as usize;
        at += 4;
        if at + data_len > buf.len() {
            return Err(AlloyError::internal(
                "the embedded asset archive ends inside a file body",
            ));
        }
        let bytes = buf[at..at + data_len].to_vec();
        at += data_len;
        files.push(AssetFile { path, bytes });
    }
    // The record set must consume the archive exactly. Trailing bytes mean
    // the buffer is not the archive the generator wrote — a truncation that
    // happened to land on a record boundary, a concatenation, or corruption
    // — and accepting them would serve a silently incomplete asset set.
    if at != buf.len() {
        return Err(AlloyError::internal(format!(
            "the embedded asset archive has {} unread trailing bytes",
            buf.len() - at
        )));
    }
    Ok(files)
}

/// Decode the generated constants into files: base64 → LZSS → archive.
pub fn decode_assets(chunks: &[&str], archive_len: usize) -> Result<Vec<AssetFile>> {
    let compressed = base64_decode_chunks(chunks)?;
    let raw = lzss_decompress(&compressed, archive_len)?;
    unpack_archive(&raw)
}

/// Seed the blob plane with any digest it does not already hold.
///
/// Because a key IS its content digest, a redundant write is a no-op and
/// concurrent replicas cannot corrupt each other — so this needs no lock for
/// correctness. The existence check is what bounds the cost: an unchanged
/// asset survives a deploy without being re-uploaded or re-fetched.
///
/// Returns the number of objects actually written.
pub async fn seed_blob(blob: &mut BlobClusterClient, files: &[AssetFile]) -> Result<usize> {
    let mut written = 0usize;
    for f in files {
        let digest = hex_digest(&f.bytes);
        if blob.get(digest.as_bytes()).await?.is_some() {
            continue;
        }
        blob.put(digest.as_bytes(), &f.bytes).await?;
        written += 1;
    }
    Ok(written)
}

/// Seed the blob plane PATH-keyed: each file is written under its served
/// path, exactly the key the gateway's content route computes
/// (`content_key`: the route's `key_prefix` plus the path suffix after the
/// route prefix). This is the seeding the deployed specs actually need —
/// `{ "prefix": "/assets/", "binding": "site", "kind": "content",
/// "key_prefix": "" }` serves `GET /assets/entry.js` from the blob key
/// `entry.js` — where the digest-keyed [`seed_blob`] serves the digest-URL
/// convention no shipped frontend uses yet.
///
/// A write is skipped when the stored bytes already match, so a restart or a
/// sibling instance re-seeding is cheap and cannot flap content. An asset
/// whose bytes CHANGED is overwritten — path keys are mutable by design, and
/// the deploy that changes them is the mutation authority.
///
/// Returns the number of objects actually written.
pub async fn seed_site(blob: &mut BlobClusterClient, files: &[AssetFile]) -> Result<usize> {
    seed_site_under(blob, "", files).await
}

/// [`seed_site`] under a blob key prefix: the content route's `key_prefix`,
/// the same prefix the api face reads assets back under.
pub async fn seed_site_under(
    blob: &mut BlobClusterClient,
    key_prefix: &str,
    files: &[AssetFile],
) -> Result<usize> {
    let mut written = 0usize;
    // The description and the stored encodings are the api face's business:
    // a blob reader sees the files as built.
    for f in served_files(files) {
        let key = format!("{key_prefix}{}", f.path);
        if let Some(existing) = blob.get(key.as_bytes()).await? {
            if existing == f.bytes {
                continue;
            }
        }
        blob.put(key.as_bytes(), &f.bytes).await?;
        written += 1;
    }
    Ok(written)
}

/// Decode the generated constants and seed the site blob path-keyed — the
/// one call an app's boot makes. Returns `(decoded, written)`.
pub async fn seed_generated(
    blob: &mut BlobClusterClient,
    chunks: &[&str],
    archive_len: usize,
) -> Result<(usize, usize)> {
    let files = decode_assets(chunks, archive_len)?;
    let written = seed_site(blob, &files).await?;
    Ok((files.len(), written))
}

/// Confirm every manifest digest is present in blob — the readiness check an
/// instance runs before reporting healthy.
pub async fn confirm_seeded(
    blob: &mut BlobClusterClient,
    manifest: &AssetManifest,
) -> Result<bool> {
    for digest in manifest.entries.values() {
        if blob.get(digest.as_bytes()).await?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The largest asset one api reply may carry.
///
/// The gateway's reply envelope is JSON on a queue whose message limit is
/// 16 MiB, and the body travels in it as an array of decimal numbers, so a
/// byte costs up to four envelope bytes. 4,193,280 bytes of arbitrary data
/// were measured to pass and 4,194,304 to fail, and the failure is silent: the
/// publish is refused and the client waits out a 504. This bound leaves 64 KiB
/// for the envelope's own fields, and an asset above it is refused by name
/// ([`AssetReply::TooLarge`]) instead of being attempted.
pub const MAX_ASSET_REPLY_BYTES: usize = 4 * 1024 * 1024 - 64 * 1024;

/// The archive record `alloy-gen` writes to describe the others: which files
/// are content-hashed, which records are `br`/`gzip` encodings of which file,
/// and the entry script and stylesheet. Hidden, so no built file collides.
pub const META_PATH: &str = ".alloy-assets.json";

/// The cache life of a content-hashed name: its bytes can never change, so a
/// browser and every shared cache may keep it for a year without asking.
pub const CACHE_IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// The cache life of an unhashed asset (`/assets/favicon.svg`, a file from
/// `web/public/`): its bytes may change in place on a deploy, so it is kept
/// five minutes and then revalidated by ETag (a 304 when nothing changed).
/// Revalidating on every navigation instead cost a round trip per file per
/// page, and those requests were left pending by every quick navigation.
pub const CACHE_SHORT: &str = "public, max-age=300";

/// The cache life of a name whose bytes change on every deploy and must
/// never be reused unchecked: an HTML document under the asset prefix, and
/// the stable `/assets/entry.js` / `/assets/entry.css` aliases of the hashed
/// entry. Revalidated by ETag on every use.
pub const CACHE_REVALIDATE: &str = "no-cache";

/// The cache life of an unhashed file: [`CACHE_REVALIDATE`] for a document,
/// [`CACHE_SHORT`] for anything else.
pub fn unhashed_cache_for(path: &str) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or(path);
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    if matches!(ext.as_str(), "html" | "htm") {
        CACHE_REVALIDATE
    } else {
        CACHE_SHORT
    }
}

/// One stored representation of an asset: its bytes and their strong ETag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Representation {
    /// The bytes as sent.
    pub bytes: Vec<u8>,
    /// The quoted SHA-256 of exactly these bytes, so each encoding of a file
    /// has its own validator and a 304 never confirms the wrong one.
    pub etag: String,
}

impl Representation {
    /// Digest `bytes` once; the api face then never hashes on a request.
    pub fn of(bytes: Vec<u8>) -> Self {
        let etag = format!("\"{}\"", hex_digest(&bytes));
        Self { bytes, etag }
    }
}

/// A served file: its identity bytes, any precompressed encodings the pack
/// step stored beside it, and the cache life the pack step decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicAsset {
    /// The file as built.
    pub identity: Representation,
    /// The Brotli encoding, when it saved at least a tenth.
    pub br: Option<Representation>,
    /// The gzip encoding, when it saved at least a tenth.
    pub gzip: Option<Representation>,
    /// [`CACHE_IMMUTABLE`], [`CACHE_SHORT`] or [`CACHE_REVALIDATE`].
    pub cache_control: &'static str,
}

impl PublicAsset {
    /// A file with no stored encodings, cached by the name heuristic: an
    /// archive packed before the description existed, or a blob read.
    pub fn identity_only(path: &str, bytes: Vec<u8>) -> Self {
        Self {
            identity: Representation::of(bytes),
            br: None,
            gzip: None,
            cache_control: cache_control_for(path),
        }
    }

    /// Whether the reply depends on `Accept-Encoding`, so must say `Vary`.
    pub fn has_encodings(&self) -> bool {
        self.br.is_some() || self.gzip.is_some()
    }
}

/// A parsed `Accept-Encoding` header (RFC 9110 §12.5.3).
#[derive(Debug, Clone, Default)]
struct AcceptEncoding {
    /// Whether the request carried the header at all.
    present: bool,
    /// Each named coding with its weight, lowercased.
    named: Vec<(String, f32)>,
    /// The weight of `*`, when listed.
    star: Option<f32>,
}

impl AcceptEncoding {
    fn parse(header: Option<&str>) -> Self {
        let Some(header) = header else {
            return Self::default();
        };
        let mut out = Self {
            present: true,
            ..Self::default()
        };
        for item in header.split(',') {
            let mut parts = item.split(';');
            let coding = parts.next().unwrap_or("").trim().to_ascii_lowercase();
            if coding.is_empty() {
                continue;
            }
            // A weight that does not parse names no acceptable coding: the
            // safe reading, since identity stays available regardless.
            let mut q = 1.0f32;
            for param in parts {
                if let Some((k, v)) = param.split_once('=') {
                    if k.trim().eq_ignore_ascii_case("q") {
                        q = v.trim().parse::<f32>().ok().filter(|q| (0.0..=1.0).contains(q)).unwrap_or(0.0);
                    }
                }
            }
            let coding = if coding == "x-gzip" { "gzip".to_string() } else { coding };
            if coding == "*" {
                out.star = Some(q);
            } else {
                out.named.push((coding, q));
            }
        }
        out
    }

    /// Whether `coding` may be sent. No header means identity only (the
    /// conservative reading every static server takes); a coding named with
    /// `q=0`, or covered only by `*;q=0`, is refused; identity is acceptable
    /// unless refused that way.
    fn allows(&self, coding: &str) -> bool {
        if !self.present {
            return coding == "identity";
        }
        if let Some((_, q)) = self.named.iter().find(|(c, _)| c == coding) {
            return *q > 0.0;
        }
        match self.star {
            Some(q) => q > 0.0,
            None => coding == "identity",
        }
    }
}

/// What the api face answers for a request under the public asset prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetReply {
    /// The asset, with the headers a static file server would send.
    Found {
        /// The bytes to send.
        bytes: Vec<u8>,
        /// The media type, from the file extension.
        content_type: &'static str,
        /// [`CACHE_IMMUTABLE`] for a content-hashed name, [`CACHE_SHORT`] for an
        /// unhashed one, [`CACHE_REVALIDATE`] for a document or a stable alias.
        cache_control: &'static str,
        /// The quoted SHA-256 of the bytes sent.
        etag: String,
        /// `br` or `gzip` for a stored encoding; `None` for identity.
        content_encoding: Option<&'static str>,
        /// `Vary: Accept-Encoding`: the path has stored encodings, so this
        /// reply was chosen by the header even when it is identity.
        vary: bool,
    },
    /// The caller already holds these bytes (`if-none-match` matched).
    NotModified {
        /// The quoted SHA-256 of the representation the caller holds.
        etag: String,
        /// The same cache life a full answer would carry.
        cache_control: &'static str,
        /// As for [`AssetReply::Found`].
        vary: bool,
    },
    /// No such asset.
    Missing,
    /// No representation the client accepts fits one api reply.
    TooLarge {
        /// The size of the smallest acceptable representation.
        size: usize,
    },
}

impl AssetReply {
    /// Judge one identity-only asset (a blob read, or a caller with bytes in
    /// hand). `if_none_match` is the request header's value where the route
    /// forwards it.
    pub fn of(path: &str, bytes: Option<Vec<u8>>, if_none_match: Option<&str>) -> Self {
        if let Some(bytes) = &bytes {
            if bytes.len() > MAX_ASSET_REPLY_BYTES {
                return AssetReply::TooLarge { size: bytes.len() };
            }
        }
        let asset = bytes.map(|bytes| PublicAsset::identity_only(path, bytes));
        Self::negotiate(path, asset.as_ref(), None, if_none_match)
    }

    /// Choose the representation of `asset` to send: Brotli, then gzip, then
    /// identity, among those `accept_encoding` allows and that fit one api
    /// reply; a larger preferred encoding gives way to a smaller one rather
    /// than failing. A client that refuses identity and every stored encoding
    /// is sent identity: an answer it can decode beats a 406 a browser never
    /// asks for. `if_none_match` is compared with the CHOSEN representation's
    /// ETag (weak comparison; `*` matches anything).
    pub fn negotiate(
        path: &str,
        asset: Option<&PublicAsset>,
        accept_encoding: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Self {
        Self::negotiate_cached(path, asset, accept_encoding, if_none_match, None)
    }

    /// [`AssetReply::negotiate`] with the asset's cache life replaced, for a
    /// stable alias of a content-hashed file: the bytes behind
    /// `/assets/entry.js` change on every deploy, so the alias revalidates.
    pub fn negotiate_cached(
        path: &str,
        asset: Option<&PublicAsset>,
        accept_encoding: Option<&str>,
        if_none_match: Option<&str>,
        cache_control: Option<&'static str>,
    ) -> Self {
        let Some(asset) = asset else {
            return AssetReply::Missing;
        };
        let cache = cache_control.unwrap_or(asset.cache_control);
        let accept = AcceptEncoding::parse(accept_encoding);
        let vary = asset.has_encodings();
        let candidates = [
            (Some("br"), asset.br.as_ref()),
            (Some("gzip"), asset.gzip.as_ref()),
            (None, Some(&asset.identity)),
        ];
        let mut acceptable: Vec<(Option<&'static str>, &Representation)> = candidates
            .iter()
            .filter_map(|(coding, rep)| rep.map(|rep| (*coding, rep)))
            .filter(|(coding, _)| accept.allows(coding.unwrap_or("identity")))
            .collect();
        if acceptable.is_empty() {
            acceptable.push((None, &asset.identity));
        }
        let Some(&(content_encoding, chosen)) = acceptable
            .iter()
            .find(|(_, rep)| rep.bytes.len() <= MAX_ASSET_REPLY_BYTES)
        else {
            let size = acceptable.iter().map(|(_, r)| r.bytes.len()).min().unwrap_or(0);
            return AssetReply::TooLarge { size };
        };
        let matched = if_none_match.is_some_and(|value| {
            value.split(',').map(str::trim).any(|tag| {
                tag == "*" || tag == chosen.etag || tag.strip_prefix("W/") == Some(chosen.etag.as_str())
            })
        });
        if matched {
            return AssetReply::NotModified {
                etag: chosen.etag.clone(),
                cache_control: cache,
                vary,
            };
        }
        AssetReply::Found {
            bytes: chosen.bytes.clone(),
            content_type: content_type_for(path),
            cache_control: cache,
            etag: chosen.etag.clone(),
            content_encoding,
            vary,
        }
    }

    /// The RFC 9457 document the two refusals carry.
    pub fn problem_json(&self) -> Option<ferrite_app::serde_json::Value> {
        match self {
            AssetReply::TooLarge { size } => Some(ferrite_app::serde_json::json!({
                "type": "urn:ferrite:problem:asset-too-large",
                "title": "Asset Too Large For One Reply",
                "status": 500,
                "retryable": false,
                "detail": format!(
                    "the smallest representation of this asset the client accepts is \
                     {size} bytes and one api reply carries at most \
                     {MAX_ASSET_REPLY_BYTES}; split it in the build, or accept br/gzip"
                ),
                "size": size,
                "limit": MAX_ASSET_REPLY_BYTES,
            })),
            AssetReply::Missing => Some(AlloyError::NotFound.problem_json()),
            _ => None,
        }
    }
}

/// The blob key (and archive path) a request path names under `prefix`, or
/// `None` when the path is outside the prefix or is not a plain file path.
///
/// The key is what the gateway's content route would have computed: the path
/// after the route prefix, query removed. A path that tries to leave the asset
/// root, names a directory, or carries a control character names nothing.
pub fn asset_key(prefix: &str, request_path: &str) -> Option<String> {
    if prefix.is_empty() {
        return None;
    }
    let path = request_path.split(['?', '#']).next().unwrap_or("");
    // A segment boundary: "/assets" serves "/assets/x", never "/assets-admin".
    let base = prefix.trim_end_matches('/');
    let suffix = path.strip_prefix(base)?.strip_prefix('/')?;
    let decoded = percent_decode(suffix)?;
    let plain = !decoded.is_empty()
        && !decoded.starts_with('/')
        && !decoded.ends_with('/')
        && !decoded.contains('\\')
        && !decoded.chars().any(char::is_control)
        && decoded.split('/').all(|part| !part.is_empty() && part != "." && part != "..");
    plain.then_some(decoded)
}

/// Percent-decode a path; `None` for a malformed escape or non-UTF-8 result.
fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hi = (*bytes.get(at + 1)? as char).to_digit(16)?;
            let lo = (*bytes.get(at + 2)? as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The media type for a served path, from its extension. Unknown extensions
/// are `application/octet-stream`, which a browser downloads and never runs.
pub fn content_type_for(path: &str) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or(path);
    let ext = match name.rsplit_once('.') {
        Some((_, ext)) => ext.to_ascii_lowercase(),
        None => String::new(),
    };
    match ext.as_str() {
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "html" | "htm" => "text/html; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

/// The name heuristic, for files the pack step did not describe (an archive
/// packed before the description existed, or a blob read): [`CACHE_IMMUTABLE`]
/// for a name that carries a content hash (`entry-DkX3f9aB.js`), otherwise
/// [`unhashed_cache_for`], since a path-keyed asset such as `entry.js` changes
/// in place on the next deploy and a year-long life would pin the old bundle.
/// A packed archive's own description wins over this.
pub fn cache_control_for(path: &str) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or(path);
    // Only the final extension comes off: `entry.client-DkX3f9aB.js` is hashed.
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    // A build hash has a digit or an inner capital; a capitalised word such as
    // `Geist-Italic-Variable` or `User-Settings` is a plain name.
    let hashed = stem.rsplit_once('-').is_some_and(|(_, tail)| {
        tail.len() >= 8
            && tail
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            && (tail.chars().any(|c| c.is_ascii_digit())
                || tail.chars().skip(1).any(|c| c.is_ascii_uppercase()))
    });
    if hashed {
        CACHE_IMMUTABLE
    } else {
        unhashed_cache_for(path)
    }
}

/// The parsed [`META_PATH`] record, when the archive carries one.
fn description(files: &[AssetFile]) -> Option<ferrite_app::serde_json::Value> {
    let meta = files.iter().find(|f| f.path == META_PATH)?;
    match ferrite_app::serde_json::from_slice(&meta.bytes) {
        Ok(value) => Some(value),
        Err(e) => {
            tracing::warn!(
                target: "alloy::assets",
                error = %e,
                "the packed asset description is not JSON; serving identity bytes with heuristic caching"
            );
            None
        }
    }
}

/// The records that are not files of their own: the description and every
/// stored encoding it names.
fn auxiliary_records(meta: Option<&ferrite_app::serde_json::Value>) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let Some(meta) = meta else {
        return out;
    };
    out.insert(META_PATH.to_string());
    if let Some(files) = meta.get("files").and_then(|f| f.as_object()) {
        for about in files.values() {
            for coding in ["br", "gzip"] {
                if let Some(path) = about.get(coding).and_then(|p| p.as_str()) {
                    out.insert(path.to_string());
                }
            }
        }
    }
    out
}

/// The files a content route or a blob reader should see: everything but the
/// description and the stored encodings, which only the api face negotiates.
pub fn served_files(files: &[AssetFile]) -> Vec<&AssetFile> {
    let skip = auxiliary_records(description(files).as_ref());
    files.iter().filter(|f| !skip.contains(&f.path)).collect()
}

/// The stable names an Alloy shell links (`/assets/entry.js`,
/// `/assets/entry.css`) under the asset prefix. A hashed build answers them
/// with the hashed entry: the runtime rewrites the shell to the hashed URLs at
/// boot, and the alias keeps a document cached before a deploy, or an old
/// link, loading.
pub const STABLE_ENTRY_JS: &str = "entry.js";
/// See [`STABLE_ENTRY_JS`].
pub const STABLE_ENTRY_CSS: &str = "entry.css";

/// The packed frontend, decoded once and held for the api face to answer from.
#[derive(Debug, Clone, Default)]
pub struct PublicAssets {
    files: BTreeMap<String, PublicAsset>,
    entry_js: Option<String>,
    entry_css: Option<String>,
    /// Stable name -> the key of the hashed file it stands for.
    aliases: BTreeMap<String, String>,
}

impl PublicAssets {
    /// Index decoded files by their served path, attaching each stored
    /// encoding to its file and taking each file's cache life from the pack
    /// step's description. Every representation is digested here, once.
    pub fn from_files(files: Vec<AssetFile>) -> Self {
        let meta = description(&files);
        let skip = auxiliary_records(meta.as_ref());
        let mut by_path: BTreeMap<String, Vec<u8>> =
            files.into_iter().map(|f| (f.path, f.bytes)).collect();
        let described = meta
            .as_ref()
            .and_then(|m| m.get("files"))
            .and_then(|f| f.as_object());
        let mut out = PublicAssets {
            entry_js: meta
                .as_ref()
                .and_then(|m| m.pointer("/entry/js"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            entry_css: meta
                .as_ref()
                .and_then(|m| m.pointer("/entry/css"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            ..PublicAssets::default()
        };
        let mut encoded: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for name in &skip {
            if let Some(bytes) = by_path.remove(name) {
                encoded.insert(name.clone(), bytes);
            }
        }
        for (path, bytes) in by_path {
            let about = described.and_then(|d| d.get(&path));
            let asset = match about {
                None => PublicAsset::identity_only(&path, bytes),
                Some(about) => {
                    let take = |coding: &str, encoded: &mut BTreeMap<String, Vec<u8>>| {
                        about
                            .get(coding)
                            .and_then(|p| p.as_str())
                            .and_then(|p| encoded.remove(p))
                            .map(Representation::of)
                    };
                    let br = take("br", &mut encoded);
                    let gzip = take("gzip", &mut encoded);
                    let immutable = about.get("immutable").and_then(|v| v.as_bool()) == Some(true);
                    PublicAsset {
                        identity: Representation::of(bytes),
                        br,
                        gzip,
                        cache_control: if immutable { CACHE_IMMUTABLE } else { unhashed_cache_for(&path) },
                    }
                }
            };
            out.files.insert(path, asset);
        }
        for (stable, url) in [(STABLE_ENTRY_JS, out.entry_js.clone()), (STABLE_ENTRY_CSS, out.entry_css.clone())] {
            let Some(url) = url else { continue };
            if out.files.contains_key(stable) {
                continue;
            }
            // The key whose URL the entry is: the longest key the URL ends with.
            let target = out
                .files
                .keys()
                .filter(|key| url.ends_with(&format!("/{key}")))
                .max_by_key(|key| key.len())
                .cloned();
            if let Some(target) = target {
                out.aliases.insert(stable.to_string(), target);
            }
        }
        out
    }

    /// The hashed file a stable entry name stands for, when `key` is one.
    pub fn alias(&self, key: &str) -> Option<&PublicAsset> {
        self.aliases.get(key).and_then(|target| self.files.get(target))
    }

    /// `shell` with its stable entry URLs (`"<prefix>entry.js"`,
    /// `"<prefix>entry.css"`, quoted as attribute values) replaced by the
    /// hashed ones, or `None` when there is nothing to replace.
    pub fn rewrite_shell(&self, shell: &str, prefix: &str) -> Option<String> {
        let mut out = shell.to_string();
        let mut changed = false;
        for (stable, hashed) in [(STABLE_ENTRY_JS, &self.entry_js), (STABLE_ENTRY_CSS, &self.entry_css)] {
            let Some(hashed) = hashed else { continue };
            if !self.aliases.contains_key(stable) {
                continue;
            }
            let from = format!("\"{prefix}{stable}\"");
            if out.contains(&from) {
                out = out.replace(&from, &format!("\"{hashed}\""));
                changed = true;
            }
        }
        changed.then_some(out)
    }

    /// The identity bytes stored under `key`.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.files.get(key).map(|a| a.identity.bytes.as_slice())
    }

    /// The asset stored under `key`, with its encodings and cache life.
    pub fn asset(&self, key: &str) -> Option<&PublicAsset> {
        self.files.get(key)
    }

    /// The entry script URL the pack step recorded from Vite's manifest.
    pub fn entry_js(&self) -> Option<&str> {
        self.entry_js.as_deref()
    }

    /// The entry stylesheet URL the pack step recorded from Vite's manifest.
    pub fn entry_css(&self) -> Option<&str> {
        self.entry_css.as_deref()
    }

    /// How many files the archive held (stored encodings not counted).
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the app packed nothing.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Vec<AssetFile> {
        vec![
            AssetFile {
                path: "index.html".into(),
                bytes: b"<!doctype html><html><body>hello hello hello</body></html>".to_vec(),
            },
            AssetFile {
                // Real binary content: the case the UTF-8 channel cannot carry.
                path: "assets/logo.png".into(),
                bytes: vec![0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0xfe, 0x00, 0x01, 0x02],
            },
        ]
    }

    #[test]
    fn base64_round_trips_including_non_utf8_bytes() {
        for case in [
            vec![],
            vec![0u8],
            vec![0u8, 255],
            vec![1, 2, 3],
            (0..=255u8).collect::<Vec<u8>>(),
        ] {
            let encoded = base64_encode(&case);
            let back = base64_decode_chunks(&[&encoded]).unwrap();
            assert_eq!(back, case, "round trip failed for {} bytes", case.len());
        }
    }

    #[test]
    fn base64_decodes_across_chunk_boundaries() {
        let data: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
        let encoded = base64_encode(&data);
        // Split at a deliberately unaligned position: chunking is part of the
        // format, so a boundary must not need to fall on a 4-character group.
        let (a, b) = encoded.split_at(7);
        let (b, c) = b.split_at(13);
        assert_eq!(base64_decode_chunks(&[a, b, c]).unwrap(), data);
    }

    #[test]
    fn invalid_base64_is_refused_rather_than_guessed() {
        assert!(base64_decode_chunks(&["not base64!!"]).is_err());
        assert!(base64_decode_chunks(&["AAAA=AAA"]).is_err());
    }

    #[test]
    fn lzss_round_trips_every_shape() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            b"a".to_vec(),
            b"abcabcabcabcabcabc".to_vec(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
            (0..=255u8).collect(),
            b"<!doctype html>".repeat(500),
        ];
        for case in cases {
            let packed = lzss_compress(&case);
            let back = lzss_decompress(&packed, case.len()).unwrap();
            assert_eq!(back, case, "lzss round trip failed at {} bytes", case.len());
        }
    }

    #[test]
    fn lzss_actually_compresses_repetitive_input() {
        let input = b"<!doctype html><html>".repeat(500);
        let packed = lzss_compress(&input);
        assert!(
            packed.len() * 4 < input.len(),
            "expected real compression, got {} from {}",
            packed.len(),
            input.len()
        );
    }

    #[test]
    fn a_malformed_stream_is_an_error_not_a_panic() {
        // A back-reference before the start of the output.
        assert!(lzss_decompress(&[0x00, 0x00, 0x05, 0x00], 8).is_err());
        // A zero distance.
        assert!(lzss_decompress(&[0x00, 0x00, 0x00, 0x00], 8).is_err());
        // Truncated inside a back-reference.
        assert!(lzss_decompress(&[0x00, 0x00], 8).is_err());
        // Declares more than it produces.
        assert!(lzss_decompress(&[0x01, b'a'], 99).is_err());
        // Claims an absurd size.
        assert!(lzss_decompress(&[], usize::MAX).is_err());
    }

    #[test]
    fn the_archive_round_trips_binary_files() {
        let input = files();
        let packed = pack_archive(&input);
        let back = unpack_archive(&packed).unwrap();
        assert_eq!(back.len(), 2);
        // Sorted by path, so the encoding is deterministic.
        assert_eq!(back[0].path, "assets/logo.png");
        assert_eq!(back[0].bytes, input[1].bytes);
        assert_eq!(back[1].path, "index.html");
    }

    #[test]
    fn packing_is_deterministic_regardless_of_input_order() {
        let mut reversed = files();
        reversed.reverse();
        assert_eq!(pack_archive(&files()), pack_archive(&reversed));
    }

    #[test]
    fn the_full_pipeline_round_trips_end_to_end() {
        let input = files();
        let raw = pack_archive(&input);
        let compressed = lzss_compress(&raw);
        let encoded = base64_encode(&compressed);
        // Emitted the way the generator writes it: many small literals.
        let chunks: Vec<&str> = encoded
            .as_bytes()
            .chunks(16)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let back = decode_assets(&chunks, raw.len()).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(
            back[0].bytes, input[1].bytes,
            "binary bytes survived the UTF-8 channel"
        );
    }

    #[test]
    fn a_truncated_archive_is_refused() {
        let packed = pack_archive(&files());
        for cut in [1usize, 4, 9, packed.len() - 1] {
            assert!(
                unpack_archive(&packed[..cut]).is_err(),
                "a {cut}-byte prefix should not unpack"
            );
        }
    }

    #[test]
    fn an_absurd_file_count_cannot_force_an_allocation() {
        // Four bytes claiming four billion files.
        let hostile = [0xff, 0xff, 0xff, 0xff];
        assert!(unpack_archive(&hostile).is_err());
    }

    #[test]
    fn a_manifest_digests_every_file_and_is_content_addressed() {
        let m = AssetManifest::of(&files(), "build-1");
        assert_eq!(m.len(), 2);
        let d = m.digest_of("index.html").unwrap();
        assert_eq!(d.len(), 64);
        assert!(d.chars().all(|c| c.is_ascii_hexdigit()));
        // Identical bytes under a different path yield the same digest, which
        // is what makes a redundant seed write a no-op.
        let same = AssetFile {
            path: "copy.html".into(),
            bytes: files()[0].bytes.clone(),
        };
        assert_eq!(hex_digest(&same.bytes), d);
    }

    #[test]
    fn an_asset_key_is_the_path_after_the_prefix_and_nothing_else() {
        assert_eq!(asset_key("/assets/", "/assets/entry.js").as_deref(), Some("entry.js"));
        assert_eq!(
            asset_key("/assets/", "/assets/img/a%20b.png?v=1").as_deref(),
            Some("img/a b.png")
        );
        for refused in [
            "/other/entry.js",
            "/assets/",
            "/assets/../secret",
            "/assets/a/../../secret",
            "/assets/%2e%2e/secret",
            "/assets//entry.js",
            "/assets/dir/",
            "/assets/a%5cb",
            "/assets/a%00b",
            "/assets/a%zz",
        ] {
            assert_eq!(asset_key("/assets/", refused), None, "{refused} named a key");
        }
        assert_eq!(asset_key("", "/assets/entry.js"), None, "an empty prefix switches it off");
    }

    #[test]
    fn a_found_asset_carries_its_type_life_and_etag() {
        let reply = AssetReply::of("entry.js", Some(b"console.log(1)".to_vec()), None);
        let AssetReply::Found { bytes, content_type, cache_control, etag, content_encoding, vary } = reply else {
            panic!("expected the asset");
        };
        assert_eq!(bytes, b"console.log(1)");
        assert_eq!(content_type, "text/javascript; charset=utf-8");
        assert_eq!(cache_control, "public, max-age=300");
        assert_eq!(content_encoding, None);
        assert!(!vary);
        assert_eq!(etag, format!("\"{}\"", hex_digest(b"console.log(1)")));

        assert_eq!(cache_control_for("chunk-DkX3f9aB.js"), "public, max-age=31536000, immutable");
        assert_eq!(cache_control_for("my-component.js"), "public, max-age=300");
        assert_eq!(content_type_for("a/b/font.WOFF2"), "font/woff2");
        assert_eq!(content_type_for("noext"), "application/octet-stream");
    }

    #[test]
    fn a_matching_etag_is_not_modified_and_a_miss_is_missing() {
        let etag = format!("\"{}\"", hex_digest(b"x"));
        let header = format!("\"other\", W/{etag}");
        assert!(matches!(
            AssetReply::of("a.css", Some(b"x".to_vec()), Some(&header)),
            AssetReply::NotModified { .. }
        ));
        assert_eq!(AssetReply::of("a.css", None, None), AssetReply::Missing);
        assert_eq!(AssetReply::Missing.problem_json().unwrap()["status"], 404);
    }

    #[test]
    fn an_asset_over_the_reply_cap_is_refused_by_name_not_attempted() {
        let at_cap = vec![0u8; MAX_ASSET_REPLY_BYTES];
        assert!(matches!(AssetReply::of("big.bin", Some(at_cap), None), AssetReply::Found { .. }));
        let over = vec![0u8; MAX_ASSET_REPLY_BYTES + 1];
        let refused = AssetReply::of("big.bin", Some(over), None);
        assert_eq!(refused, AssetReply::TooLarge { size: MAX_ASSET_REPLY_BYTES + 1 });
        let doc = refused.problem_json().unwrap();
        assert_eq!(doc["type"], "urn:ferrite:problem:asset-too-large");
        assert_eq!(doc["limit"], MAX_ASSET_REPLY_BYTES);
    }

    #[test]
    fn the_decoded_archive_answers_by_served_path() {
        let held = PublicAssets::from_files(files());
        assert_eq!(held.len(), files().len());
        let first = &files()[0];
        assert_eq!(held.get(&first.path), Some(first.bytes.as_slice()));
        assert_eq!(held.get("absent.js"), None);
    }

    /// A packed archive as `alloy-gen` writes it: a hashed script with both
    /// encodings, an unhashed image, and the description.
    fn described_files() -> Vec<AssetFile> {
        let meta = br#"{"version":1,"entry":{"js":"/assets/entry-AbC12345.js"},"files":{"entry-AbC12345.js":{"immutable":true,"br":"entry-AbC12345.js.br","gzip":"entry-AbC12345.js.gz"},"img/logo.webp":{"immutable":false}}}"#;
        vec![
            AssetFile { path: "entry-AbC12345.js".into(), bytes: b"console.log('identity identity')".to_vec() },
            AssetFile { path: "entry-AbC12345.js.br".into(), bytes: b"BR".to_vec() },
            AssetFile { path: "entry-AbC12345.js.gz".into(), bytes: b"GZIP".to_vec() },
            AssetFile { path: "img/logo.webp".into(), bytes: vec![0x52, 0x49, 0x46, 0x46] },
            AssetFile { path: META_PATH.into(), bytes: meta.to_vec() },
        ]
    }

    fn found(reply: AssetReply) -> (Vec<u8>, Option<&'static str>, bool, String, &'static str) {
        match reply {
            AssetReply::Found { bytes, content_encoding, vary, etag, cache_control, .. } => {
                (bytes, content_encoding, vary, etag, cache_control)
            }
            other => panic!("expected the asset, got {other:?}"),
        }
    }

    #[test]
    fn the_description_attaches_encodings_and_decides_the_cache_life() {
        let held = PublicAssets::from_files(described_files());
        assert_eq!(held.len(), 2, "encodings and the description are not files of their own");
        assert_eq!(held.get("entry-AbC12345.js.br"), None);
        assert_eq!(held.get(META_PATH), None);
        assert_eq!(held.entry_js(), Some("/assets/entry-AbC12345.js"));
        let script = held.asset("entry-AbC12345.js").unwrap();
        assert!(script.has_encodings());
        assert_eq!(script.cache_control, CACHE_IMMUTABLE);
        let image = held.asset("img/logo.webp").unwrap();
        assert!(!image.has_encodings());
        assert_eq!(image.cache_control, CACHE_SHORT);
        let files = described_files();
        let seeded: Vec<&str> = served_files(&files).iter().map(|f| f.path.as_str()).collect();
        assert_eq!(seeded, vec!["entry-AbC12345.js", "img/logo.webp"]);
    }

    #[test]
    fn an_archive_without_a_description_serves_identity_by_the_name_heuristic() {
        let held = PublicAssets::from_files(vec![
            AssetFile { path: "entry.js".into(), bytes: b"x".to_vec() },
            AssetFile { path: "chunk-DkX3f9aB.js".into(), bytes: b"y".to_vec() },
        ]);
        assert_eq!(held.asset("entry.js").unwrap().cache_control, CACHE_SHORT);
        assert_eq!(held.asset("chunk-DkX3f9aB.js").unwrap().cache_control, CACHE_IMMUTABLE);
        assert!(!held.asset("entry.js").unwrap().has_encodings());
    }

    #[test]
    fn negotiation_prefers_br_then_gzip_then_identity_and_always_varies() {
        let held = PublicAssets::from_files(described_files());
        let asset = held.asset("entry-AbC12345.js");
        let pick = |accept: Option<&str>| found(AssetReply::negotiate("entry-AbC12345.js", asset, accept, None));

        let (bytes, coding, vary, _, cache) = pick(Some("gzip, deflate, br, zstd"));
        assert_eq!((bytes.as_slice(), coding, vary, cache), (&b"BR"[..], Some("br"), true, CACHE_IMMUTABLE));
        assert_eq!(pick(Some("gzip")).1, Some("gzip"));
        assert_eq!(pick(Some("x-gzip")).1, Some("gzip"));
        assert_eq!(pick(Some("br;q=0, gzip;q=0.5")).1, Some("gzip"), "q=0 refuses br");
        assert_eq!(pick(Some("*")).1, Some("br"), "* accepts every coding not named");
        assert_eq!(pick(Some("br;q=0, *")).1, Some("gzip"));
        // Identity replies for a path with encodings still vary.
        let (bytes, coding, vary, _, _) = pick(None);
        assert_eq!((coding, vary), (None, true));
        assert_eq!(bytes, b"console.log('identity identity')");
        assert_eq!(pick(Some("identity")).1, None);
        assert_eq!(pick(Some("deflate")).1, None, "an unknown coding falls back to identity");
        assert_eq!(pick(Some("*;q=0, gzip")).1, Some("gzip"));
        // Refusing identity and every stored coding still gets a decodable answer.
        assert_eq!(pick(Some("identity;q=0, br;q=0, gzip;q=0")).1, None);
        assert_eq!(pick(Some("br;q=bogus")).1, None, "an unreadable weight accepts nothing");

        // A path without encodings never varies.
        let image = held.asset("img/logo.webp");
        let (_, coding, vary, _, cache) = found(AssetReply::negotiate("img/logo.webp", image, Some("br"), None));
        assert_eq!((coding, vary, cache), (None, false, CACHE_SHORT));
        assert_eq!(unhashed_cache_for("page/index.html"), CACHE_REVALIDATE, "a document always revalidates");
    }

    #[test]
    fn each_representation_has_its_own_etag_and_304() {
        let held = PublicAssets::from_files(described_files());
        let asset = held.asset("entry-AbC12345.js");
        let (_, _, _, br_etag, _) = found(AssetReply::negotiate("entry-AbC12345.js", asset, Some("br"), None));
        let (_, _, _, id_etag, _) = found(AssetReply::negotiate("entry-AbC12345.js", asset, None, None));
        assert_ne!(br_etag, id_etag);
        assert_eq!(id_etag, format!("\"{}\"", hex_digest(b"console.log('identity identity')")));

        let weak = format!("W/{br_etag}");
        assert_eq!(
            AssetReply::negotiate("entry-AbC12345.js", asset, Some("br"), Some(&weak)),
            AssetReply::NotModified { etag: br_etag.clone(), cache_control: CACHE_IMMUTABLE, vary: true }
        );
        // The br validator does not confirm the identity bytes.
        assert!(matches!(
            AssetReply::negotiate("entry-AbC12345.js", asset, None, Some(&br_etag)),
            AssetReply::Found { .. }
        ));
        assert!(matches!(
            AssetReply::negotiate("entry-AbC12345.js", asset, None, Some("*")),
            AssetReply::NotModified { vary: true, .. }
        ));
    }

    #[test]
    fn a_representation_over_the_reply_cap_gives_way_to_a_smaller_one() {
        let big = vec![b'a'; MAX_ASSET_REPLY_BYTES + 1];
        let asset = PublicAsset {
            identity: Representation::of(big.clone()),
            br: Some(Representation::of(big)),
            gzip: Some(Representation::of(b"small".to_vec())),
            cache_control: CACHE_IMMUTABLE,
        };
        let (bytes, coding, ..) = found(AssetReply::negotiate("a.js", Some(&asset), Some("br, gzip"), None));
        assert_eq!((bytes.as_slice(), coding), (&b"small"[..], Some("gzip")));
        assert_eq!(
            AssetReply::negotiate("a.js", Some(&asset), Some("br"), None),
            AssetReply::TooLarge { size: MAX_ASSET_REPLY_BYTES + 1 }
        );
    }

    #[test]
    fn the_stable_entry_names_alias_the_hashed_files_and_the_shell_is_rewritten() {
        let held = PublicAssets::from_files(described_files());
        let alias = held.alias(STABLE_ENTRY_JS).expect("entry.js stands for the hashed entry");
        assert_eq!(alias, held.asset("entry-AbC12345.js").unwrap());
        assert!(held.alias(STABLE_ENTRY_CSS).is_none(), "no stylesheet was packed");
        assert!(held.alias("entry-AbC12345.js").is_none());
        // The alias revalidates: its bytes change on every deploy.
        let reply = AssetReply::negotiate_cached("entry.js", Some(alias), Some("br"), None, Some(CACHE_REVALIDATE));
        let (bytes, coding, vary, _, cache) = found(reply);
        assert_eq!((bytes.as_slice(), coding, vary, cache), (&b"BR"[..], Some("br"), true, CACHE_REVALIDATE));

        let shell = r#"<link rel="stylesheet" href="/assets/entry.css"><script type="module" src="/assets/entry.js"></script>"#;
        let rewritten = held.rewrite_shell(shell, "/assets/").unwrap();
        assert!(rewritten.contains(r#"src="/assets/entry-AbC12345.js""#), "{rewritten}");
        assert!(rewritten.contains(r#"href="/assets/entry.css""#), "an unpacked stylesheet keeps its name");
        assert_eq!(held.rewrite_shell("<p>no entry</p>", "/assets/"), None);
        // An archive that still holds entry.js itself is served as built.
        let pinned = PublicAssets::from_files(vec![AssetFile { path: "entry.js".into(), bytes: b"x".to_vec() }]);
        assert!(pinned.alias(STABLE_ENTRY_JS).is_none());
        assert_eq!(pinned.rewrite_shell(shell, "/assets/"), None);
    }
}
