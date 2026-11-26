//! The router: strict path canonicalization, file-convention route
//! patterns (static, dynamic `[x]`, catch-all `[...x]`, optional
//! catch-all `[[...x]]`) with the normative precedence static, then
//! dynamic, then catch-all, then optional catch-all (codegen-v1 §4), and
//! the canonical query parser (one decoder for the whole framework).
//!
//! ## Why canonicalization is its own step
//!
//! Authorization middleware compares paths. If middleware sees a
//! different string from the one the router matches, the two can
//! disagree — the classic `/public/%2e%2e/admin` bypass
//! (adversarial review ALY-ROUTE-002/003). So a request is canonicalized
//! ONCE, before any application code runs: each segment is strictly
//! percent-decoded exactly once, and anything ambiguous is REFUSED
//! rather than guessed — encoded separators, dot segments, control
//! bytes, invalid UTF-8, empty segments. Middleware, matching, params
//! and `RouteCtx::path()` then all read the same canonical value.

use std::collections::{BTreeMap, HashSet};

/// Decode `%XX` escapes permissively; invalid escapes pass through
/// verbatim. When `plus_as_space`, `+` decodes to a space. This is the
/// QUERY decoder — paths use the strict segment decoder instead.
pub fn percent_decode(s: &str, plus_as_space: bool) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse a query string into decoded pairs (order preserved, duplicates
/// kept): split on `&`, first `=` splits name/value, a pair without `=`
/// becomes `(name, "")`, `+` decodes as space, invalid escapes verbatim.
pub fn parse_query(raw: &str) -> Vec<(String, String)> {
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((n, v)) => (percent_decode(n, true), percent_decode(v, true)),
            None => (percent_decode(pair, true), String::new()),
        })
        .collect()
}

/// Why a request path was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// The whole path exceeds the byte limit.
    TooLong,
    /// The path has more segments than the limit.
    TooManySegments,
    /// One segment exceeds the byte limit.
    SegmentTooLong,
    /// An empty segment (`//`) — ambiguous, never guessed.
    EmptySegment,
    /// A `.` or `..` segment, raw or encoded.
    DotSegment,
    /// A percent-encoded `/` or `\` inside a segment.
    EncodedSeparator,
    /// A control byte (including NUL) anywhere in the path.
    ControlByte,
    /// A malformed percent escape.
    InvalidEncoding,
    /// Decoded bytes that are not valid UTF-8.
    NotUtf8,
}

impl PathError {
    /// The HTTP status this refusal answers with.
    pub fn status(&self) -> u16 {
        match self {
            PathError::TooLong | PathError::TooManySegments | PathError::SegmentTooLong => 414,
            _ => 400,
        }
    }

    /// A stable machine-readable reason.
    pub fn code(&self) -> &'static str {
        match self {
            PathError::TooLong => "path_too_long",
            PathError::TooManySegments => "too_many_segments",
            PathError::SegmentTooLong => "segment_too_long",
            PathError::EmptySegment => "empty_segment",
            PathError::DotSegment => "dot_segment",
            PathError::EncodedSeparator => "encoded_separator",
            PathError::ControlByte => "control_byte",
            PathError::InvalidEncoding => "invalid_encoding",
            PathError::NotUtf8 => "invalid_utf8",
        }
    }
}

/// Bounds applied while canonicalizing a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathLimits {
    /// Maximum raw path bytes.
    pub max_bytes: usize,
    /// Maximum number of segments.
    pub max_segments: usize,
    /// Maximum bytes in one segment.
    pub max_segment_bytes: usize,
}

impl Default for PathLimits {
    fn default() -> Self {
        Self {
            max_bytes: 4096,
            max_segments: 64,
            max_segment_bytes: 512,
        }
    }
}

fn decode_segment(raw: &str) -> Result<String, PathError> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(PathError::InvalidEncoding);
                }
                let hi = (bytes[i + 1] as char)
                    .to_digit(16)
                    .ok_or(PathError::InvalidEncoding)?;
                let lo = (bytes[i + 2] as char)
                    .to_digit(16)
                    .ok_or(PathError::InvalidEncoding)?;
                let b = (hi * 16 + lo) as u8;
                match b {
                    b'/' | b'\\' => return Err(PathError::EncodedSeparator),
                    b if b < 0x20 || b == 0x7f => return Err(PathError::ControlByte),
                    b => out.push(b),
                }
                i += 3;
            }
            b'\\' => return Err(PathError::EncodedSeparator),
            b if b < 0x20 || b == 0x7f => return Err(PathError::ControlByte),
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| PathError::NotUtf8)
}

/// A validated, decoded request path: the single representation
/// middleware, matching, and params all read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPath {
    segments: Vec<String>,
    canonical: String,
}

impl CanonicalPath {
    /// Canonicalize a raw request path (query already stripped).
    pub fn parse(raw: &str, limits: &PathLimits) -> Result<Self, PathError> {
        if raw.len() > limits.max_bytes {
            return Err(PathError::TooLong);
        }
        if raw.is_empty() || raw == "/" {
            return Ok(Self {
                segments: Vec::new(),
                canonical: "/".to_string(),
            });
        }
        let body = raw.strip_prefix('/').unwrap_or(raw);
        // Exactly ONE trailing slash normalizes away (`/blog/` == `/blog`).
        // Anything beyond that is an empty segment, which is ambiguous and
        // therefore refused rather than silently collapsed.
        let body = body.strip_suffix('/').unwrap_or(body);
        if body.is_empty() {
            return Err(PathError::EmptySegment);
        }
        let raw_segments: Vec<&str> = body.split('/').collect();
        if raw_segments.len() > limits.max_segments {
            return Err(PathError::TooManySegments);
        }
        let mut segments = Vec::with_capacity(raw_segments.len());
        for raw_seg in raw_segments {
            if raw_seg.is_empty() {
                return Err(PathError::EmptySegment);
            }
            if raw_seg.len() > limits.max_segment_bytes {
                return Err(PathError::SegmentTooLong);
            }
            let decoded = decode_segment(raw_seg)?;
            if decoded == "." || decoded == ".." {
                return Err(PathError::DotSegment);
            }
            if decoded.is_empty() {
                return Err(PathError::EmptySegment);
            }
            segments.push(decoded);
        }
        let canonical = format!("/{}", segments.join("/"));
        Ok(Self {
            segments,
            canonical,
        })
    }

    /// The decoded, validated segments.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// The canonical decoded path string (`/a/b`, or `/` for the root).
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}

/// One pattern segment.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    Static(String),
    Param(String),
    CatchAll(String),
    OptCatchAll(String),
}

impl Seg {
    fn rank(&self) -> u8 {
        match self {
            Seg::Static(_) => 0,
            Seg::Param(_) => 1,
            Seg::CatchAll(_) => 2,
            Seg::OptCatchAll(_) => 3,
        }
    }

    /// The shape signature used for duplicate detection: parameter NAMES
    /// do not distinguish two routes.
    fn shape(&self) -> String {
        match self {
            Seg::Static(s) => format!("s:{s}"),
            Seg::Param(_) => "p".into(),
            Seg::CatchAll(_) => "c".into(),
            Seg::OptCatchAll(_) => "o".into(),
        }
    }

    fn param_name(&self) -> Option<&str> {
        match self {
            Seg::Static(_) => None,
            Seg::Param(n) | Seg::CatchAll(n) | Seg::OptCatchAll(n) => Some(n),
        }
    }
}

fn parse_segment(raw: &str) -> Result<Seg, String> {
    if let Some(inner) = raw.strip_prefix("[[").and_then(|r| r.strip_suffix("]]")) {
        let name = inner
            .strip_prefix("...")
            .ok_or_else(|| format!("optional catch-all must be [[...name]], got '{raw}'"))?;
        if name.is_empty() {
            return Err(format!("empty parameter name in '{raw}'"));
        }
        return Ok(Seg::OptCatchAll(name.to_string()));
    }
    if let Some(inner) = raw.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        if let Some(name) = inner.strip_prefix("...") {
            if name.is_empty() {
                return Err(format!("empty parameter name in '{raw}'"));
            }
            return Ok(Seg::CatchAll(name.to_string()));
        }
        if inner.is_empty() {
            return Err(format!("empty parameter name in '{raw}'"));
        }
        return Ok(Seg::Param(inner.to_string()));
    }
    if raw.is_empty() {
        return Err("empty static segment".into());
    }
    if raw == "." || raw == ".." {
        return Err(format!("dot segments are not routable: '{raw}'"));
    }
    Ok(Seg::Static(raw.to_string()))
}

/// A parsed route pattern.
#[derive(Debug, Clone)]
struct Pattern {
    segs: Vec<Seg>,
}

impl Pattern {
    fn parse(pattern: &str) -> Result<Self, String> {
        let trimmed = pattern.strip_prefix('/').unwrap_or(pattern);
        let trimmed = trimmed.trim_end_matches('/');
        let mut segs = Vec::new();
        if !trimmed.is_empty() {
            for raw in trimmed.split('/') {
                segs.push(parse_segment(raw)?);
            }
        }
        for (i, s) in segs.iter().enumerate() {
            if matches!(s, Seg::CatchAll(_) | Seg::OptCatchAll(_)) && i + 1 != segs.len() {
                return Err(format!("catch-all must be the final segment in '{pattern}'"));
            }
        }
        // A repeated capture name would silently overwrite an earlier
        // capture (ALY-ROUTE-004): refuse the pattern instead.
        let mut names = HashSet::new();
        for s in &segs {
            if let Some(name) = s.param_name() {
                if !names.insert(name.to_string()) {
                    return Err(format!(
                        "parameter '{name}' is captured twice in '{pattern}'"
                    ));
                }
            }
        }
        Ok(Self { segs })
    }

    fn shape(&self) -> String {
        self.segs
            .iter()
            .map(|s| s.shape())
            .collect::<Vec<_>>()
            .join("/")
    }

    /// The specificity vector, without capturing.
    fn spec_of(&self) -> Vec<u8> {
        self.segs.iter().map(|s| s.rank()).collect()
    }

    /// Does this pattern match, and if so with what specificity? Captures
    /// are NOT materialized here (ALY-ROUTE-005: losers never allocate).
    fn matches(&self, parts: &[String]) -> Option<Vec<u8>> {
        let mut i = 0usize;
        for seg in &self.segs {
            match seg {
                Seg::Static(want) => {
                    if parts.get(i).map(|p| p == want) != Some(true) {
                        return None;
                    }
                    i += 1;
                }
                Seg::Param(_) => {
                    let part = parts.get(i)?;
                    if part.is_empty() {
                        return None;
                    }
                    i += 1;
                }
                Seg::CatchAll(_) => {
                    if i >= parts.len() {
                        return None;
                    }
                    i = parts.len();
                }
                Seg::OptCatchAll(_) => {
                    i = parts.len();
                }
            }
        }
        (i == parts.len()).then(|| self.spec_of())
    }

    /// Materialize captures for a pattern already known to match.
    fn capture(&self, parts: &[String]) -> Params {
        let mut params = BTreeMap::new();
        let mut i = 0usize;
        for seg in &self.segs {
            match seg {
                Seg::Static(_) => i += 1,
                Seg::Param(name) => {
                    if let Some(p) = parts.get(i) {
                        params.insert(name.clone(), p.clone());
                    }
                    i += 1;
                }
                Seg::CatchAll(name) | Seg::OptCatchAll(name) => {
                    params.insert(name.clone(), parts[i.min(parts.len())..].join("/"));
                    i = parts.len();
                }
            }
        }
        Params(params)
    }
}

/// The shape signature of a route pattern (parameter names excluded).
/// Two patterns with the same shape address the same paths.
pub fn route_shape(pattern: &str) -> Result<String, String> {
    Ok(Pattern::parse(pattern)?.shape())
}

/// Captured route parameters (strictly decoded, separator-free).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params(BTreeMap<String, String>);

impl Params {
    /// No parameters.
    pub fn empty() -> Self {
        Self(BTreeMap::new())
    }

    /// A captured parameter by name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(|s| s.as_str())
    }

    /// Iterate captured `(name, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The number of captured parameters.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no parameters were captured.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A successful match.
pub struct RouteMatch<'a, T> {
    /// The matched route's value.
    pub value: &'a T,
    /// The captured parameters.
    pub params: Params,
    /// The specificity vector (lexicographically smaller wins).
    pub spec: Vec<u8>,
}

/// A route table over values of `T`.
pub struct Router<T> {
    routes: Vec<(Pattern, T)>,
    shapes: HashSet<String>,
}

impl<T> Default for Router<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Router<T> {
    /// An empty table.
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            shapes: HashSet::new(),
        }
    }

    /// Register a pattern. Refuses malformed patterns, repeated capture
    /// names, and duplicate shapes (parameter names do not distinguish
    /// shapes). Registration is O(1) per route.
    pub fn add(&mut self, pattern: &str, value: T) -> Result<(), String> {
        let p = Pattern::parse(pattern)?;
        let shape = p.shape();
        if !self.shapes.insert(shape) {
            return Err(format!("duplicate route shape for '{pattern}'"));
        }
        self.routes.push((p, value));
        Ok(())
    }

    /// Whether a shape is already registered.
    pub fn has_shape(&self, shape: &str) -> bool {
        self.shapes.contains(shape)
    }

    /// Match canonical segments. Precedence: the lexicographically
    /// smallest specificity vector wins (static=0 < dynamic=1 <
    /// catch-all=2 < optional=3), which yields the documented resolution
    /// order. Only the winner materializes captures.
    pub fn match_segments(&self, parts: &[String]) -> Option<RouteMatch<'_, T>> {
        let mut best: Option<(Vec<u8>, &Pattern, &T)> = None;
        for (pattern, value) in &self.routes {
            if let Some(spec) = pattern.matches(parts) {
                let better = match &best {
                    None => true,
                    Some((best_spec, _, _)) => spec < *best_spec,
                };
                if better {
                    best = Some((spec, pattern, value));
                }
            }
        }
        best.map(|(spec, pattern, value)| RouteMatch {
            value,
            params: pattern.capture(parts),
            spec,
        })
    }

    /// Canonicalize `path` with default limits and match it. Returns
    /// `None` when the path is refused or unmatched (tests and callers
    /// that need the refusal reason use [`CanonicalPath::parse`]).
    pub fn match_path(&self, path: &str) -> Option<RouteMatch<'_, T>> {
        let canon = CanonicalPath::parse(path, &PathLimits::default()).ok()?;
        self.match_segments(canon.segments())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router(patterns: &[&str]) -> Router<String> {
        let mut r = Router::new();
        for p in patterns {
            r.add(p, p.to_string()).expect("pattern registers");
        }
        r
    }

    fn hit<'a>(r: &'a Router<String>, path: &str) -> Option<(&'a str, Params)> {
        r.match_path(path).map(|m| (m.value.as_str(), m.params))
    }

    #[test]
    fn static_and_root_match() {
        let r = router(&["/", "/blog", "/blog/featured"]);
        assert_eq!(hit(&r, "/").unwrap().0, "/");
        assert_eq!(hit(&r, "/blog").unwrap().0, "/blog");
        assert_eq!(hit(&r, "/blog/featured").unwrap().0, "/blog/featured");
        assert!(hit(&r, "/nope").is_none());
    }

    #[test]
    fn dynamic_captures_and_percent_decodes() {
        let r = router(&["/blog/[slug]"]);
        let (v, p) = hit(&r, "/blog/hello-world").unwrap();
        assert_eq!(v, "/blog/[slug]");
        assert_eq!(p.get("slug"), Some("hello-world"));
        // ordinary percent-encoding decodes
        let (_, p) = hit(&r, "/blog/a%20b").unwrap();
        assert_eq!(p.get("slug"), Some("a b"));
        // unicode round-trips
        let (_, p) = hit(&r, "/blog/caf%C3%A9").unwrap();
        assert_eq!(p.get("slug"), Some("caf\u{e9}"));
    }

    #[test]
    fn precedence_static_beats_dynamic_beats_catchall() {
        let r = router(&["/blog/[slug]", "/blog/featured", "/[...rest]"]);
        assert_eq!(hit(&r, "/blog/featured").unwrap().0, "/blog/featured");
        assert_eq!(hit(&r, "/blog/other").unwrap().0, "/blog/[slug]");
        assert_eq!(hit(&r, "/anything/else").unwrap().0, "/[...rest]");
        let (_, p) = hit(&r, "/a/b/c").unwrap();
        assert_eq!(p.get("rest"), Some("a/b/c"));
    }

    #[test]
    fn precedence_holds_across_different_pattern_lengths() {
        let r = router(&["/a", "/a/[[...tail]]", "/[x]", "/[x]/[[...tail]]"]);
        assert_eq!(hit(&r, "/a").unwrap().0, "/a");
        assert_eq!(hit(&r, "/b").unwrap().0, "/[x]");
        assert_eq!(hit(&r, "/a/deep/er").unwrap().0, "/a/[[...tail]]");
    }

    #[test]
    fn catch_all_requires_one_segment_optional_matches_zero() {
        let r = router(&["/docs/[...path]"]);
        assert!(hit(&r, "/docs").is_none());
        assert_eq!(hit(&r, "/docs/a/b").unwrap().1.get("path"), Some("a/b"));
        let r = router(&["/docs/[[...path]]"]);
        assert_eq!(hit(&r, "/docs").unwrap().1.get("path"), Some(""));
        assert_eq!(hit(&r, "/docs/a").unwrap().1.get("path"), Some("a"));
    }

    #[test]
    fn duplicates_and_malformed_patterns_are_refused() {
        let mut r: Router<u32> = Router::new();
        r.add("/blog/[slug]", 1).unwrap();
        assert!(r.add("/blog/[id]", 2).is_err(), "same shape, different name");
        assert!(r.add("/x/[...a]/y", 3).is_err(), "catch-all must be final");
        assert!(r.add("/x/[]", 4).is_err(), "empty param name");
        assert!(r.add("/x//y", 5).is_err(), "empty static segment");
        assert!(r.add("/x/../y", 6).is_err(), "dot segments are not routable");
    }

    /// ALY-ROUTE-004: a repeated capture name silently lost a value.
    #[test]
    fn repeated_parameter_names_are_refused() {
        let mut r: Router<u32> = Router::new();
        assert!(r.add("/[id]/[id]", 1).is_err());
        assert!(r.add("/[id]/[...id]", 2).is_err());
        assert!(r.add("/[a]/[b]", 3).is_ok());
    }

    /// ALY-ROUTE-002/003: the canonicalizer refuses every ambiguous form.
    #[test]
    fn canonicalization_refuses_ambiguous_paths() {
        let l = PathLimits::default();
        let cases: &[(&str, PathError)] = &[
            ("/public/../admin", PathError::DotSegment),
            ("/public/%2e%2e/admin", PathError::DotSegment),
            ("/public/%2E%2E/admin", PathError::DotSegment),
            ("/public/./admin", PathError::DotSegment),
            ("/blog/a%2Fb", PathError::EncodedSeparator),
            ("/docs/%5Cadmin", PathError::EncodedSeparator),
            ("/docs/a\\b", PathError::EncodedSeparator),
            ("/docs//admin", PathError::EmptySegment),
            ("/docs//", PathError::EmptySegment),
            ("//", PathError::EmptySegment),
            ("/a///", PathError::EmptySegment),
            ("/docs/%00", PathError::ControlByte),
            ("/docs/%FF", PathError::NotUtf8),
            ("/docs/%zz", PathError::InvalidEncoding),
            ("/docs/%2", PathError::InvalidEncoding),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                CanonicalPath::parse(raw, &l).unwrap_err(),
                *expected,
                "{raw} must be refused as {expected:?}"
            );
        }
    }

    #[test]
    fn canonicalization_normalizes_and_decodes() {
        let l = PathLimits::default();
        let c = CanonicalPath::parse("/blog/", &l).unwrap();
        assert_eq!(c.as_str(), "/blog");
        assert_eq!(c.segments(), &["blog".to_string()]);

        let root = CanonicalPath::parse("/", &l).unwrap();
        assert_eq!(root.as_str(), "/");
        assert!(root.segments().is_empty());

        let decoded = CanonicalPath::parse("/a%20b/c", &l).unwrap();
        assert_eq!(decoded.as_str(), "/a b/c");
        // the canonical form is what middleware compares against
        assert_eq!(decoded.segments(), &["a b".to_string(), "c".to_string()]);
    }

    #[test]
    fn canonicalization_enforces_limits() {
        let tight = PathLimits {
            max_bytes: 16,
            max_segments: 2,
            max_segment_bytes: 4,
        };
        assert_eq!(
            CanonicalPath::parse("/aaaaaaaaaaaaaaaaaaaa", &tight).unwrap_err(),
            PathError::TooLong
        );
        assert_eq!(
            CanonicalPath::parse("/a/b/c", &tight).unwrap_err(),
            PathError::TooManySegments
        );
        assert_eq!(
            CanonicalPath::parse("/abcdefg", &tight).unwrap_err(),
            PathError::SegmentTooLong
        );
        assert_eq!(PathError::TooLong.status(), 414);
        assert_eq!(PathError::DotSegment.status(), 400);
    }

    #[test]
    fn the_canonical_query_parser() {
        assert_eq!(
            parse_query("page=2&sort=asc"),
            vec![("page".into(), "2".into()), ("sort".into(), "asc".into())]
        );
        assert_eq!(
            parse_query("q=a+b%20c&flag"),
            vec![("q".into(), "a b c".into()), ("flag".into(), String::new())]
        );
        assert_eq!(
            parse_query("x=%GG&x=2"),
            vec![("x".into(), "%GG".into()), ("x".into(), "2".into())]
        );
        assert_eq!(parse_query(""), Vec::<(String, String)>::new());
    }

    #[test]
    fn route_shapes_ignore_parameter_names() {
        assert_eq!(
            route_shape("/blog/[slug]").unwrap(),
            route_shape("/blog/[id]").unwrap()
        );
        assert_ne!(
            route_shape("/blog/[slug]").unwrap(),
            route_shape("/blog/featured").unwrap()
        );
    }
}
