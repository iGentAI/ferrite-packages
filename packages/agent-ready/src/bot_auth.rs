//! Web Bot Auth surface (draft-meunier-webbotauth / RFC 9421 subset).
//!
//! The constrained tier cannot fetch a key directory or verify Ed25519
//! signatures itself without vendoring the primitive, so this module carries
//! the PARSING half and the POLICY half: parse `Signature-Agent` /
//! `Signature-Input` / `Signature` header values into a structured claim,
//! classify the caller, and let the app act on a verdict that an edge
//! verifier (or a test harness) injects.
//!
//! The verification itself is the platform gateway's job (a filed platform
//! proposal); apps built on this module
//! become agent-aware with an `if` statement the moment the edge starts
//! stamping verdicts.

/// Who is calling, as far as the serving app can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerClass {
    /// A verified agent identity: the edge checked an RFC 9421 signature
    /// against the agent's published key directory.
    Verified {
        /// The `Signature-Agent` directory URL (the agent's identity).
        agent: String,
    },
    /// The caller DECLARED an agent identity (headers present) but no
    /// verifier has confirmed it.
    Declared {
        /// The claimed `Signature-Agent` directory URL.
        agent: String,
    },
    /// No agent identity headers at all.
    Anonymous,
}

impl CallerClass {
    /// A short label for logs and problem details.
    pub fn label(&self) -> &'static str {
        match self {
            CallerClass::Verified { .. } => "verified",
            CallerClass::Declared { .. } => "declared",
            CallerClass::Anonymous => "anonymous",
        }
    }
}

/// Strip optional double quotes from a header token (the `Signature-Agent`
/// value is an sf-string per the draft: `"https://signer.example.com"`).
fn unquote(v: &str) -> &str {
    let v = v.trim();
    v.strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(v)
}

/// Classify a caller from the (possibly absent) Web Bot Auth headers.
///
/// `verified` is the edge/harness verdict: `true` only when a verifier has
/// actually checked the signature against the agent's key directory. The
/// constrained app never claims verification it did not receive.
pub fn classify(
    signature_agent: Option<&str>,
    signature_input: Option<&str>,
    signature: Option<&str>,
    verified: bool,
) -> CallerClass {
    match signature_agent {
        Some(agent) if !unquote(agent).trim().is_empty() => {
            let agent = unquote(agent).to_string();
            let has_sig = signature_input.is_some() && signature.is_some();
            if verified && has_sig {
                CallerClass::Verified { agent }
            } else {
                CallerClass::Declared { agent }
            }
        }
        _ => CallerClass::Anonymous,
    }
}

/// Parse the covered components + keyid + tag out of a `Signature-Input`
/// header value (RFC 9421 structured-field subset, e.g.
/// `sig2=("@authority" "signature-agent");created=1735689600;keyid="...";tag="web-bot-auth"`).
/// Returns the FIRST signature entry, parsed strictly as an RFC 8941
/// dictionary member: the inner list must follow `=` directly, quoted
/// strings honour `\` escapes, and parameters stop at the first unquoted
/// `,`, so a later member can never lend its `keyid`, `tag` or `expires` to
/// the first. Anything malformed is `None`.
pub fn parse_signature_input(v: &str) -> Option<SignatureInput> {
    let mut p = SfParser { s: v.trim().as_bytes(), i: 0 };
    let label = p.token()?;
    p.expect(b'=')?;
    p.expect(b'(')?;
    let mut comps = Vec::new();
    loop {
        p.skip_spaces();
        match p.peek()? {
            b')' => {
                p.i += 1;
                break;
            }
            b'"' => comps.push(p.quoted()?),
            _ => return None,
        }
        match p.peek()? {
            b' ' | b')' => {}
            _ => return None,
        }
    }
    let mut keyid = None;
    let mut tag = None;
    let mut created = None;
    let mut expires = None;
    loop {
        match p.peek() {
            None | Some(b',') => break,
            Some(b';') => p.i += 1,
            Some(_) => return None,
        }
        p.skip_spaces();
        let key = p.token()?;
        p.expect(b'=')?;
        let value = match p.peek()? {
            b'"' => SfValue::Text(p.quoted()?),
            b'0'..=b'9' => SfValue::Integer(p.integer()?),
            _ => SfValue::Text(p.token()?),
        };
        match (key.as_str(), value) {
            ("keyid", SfValue::Text(v)) => keyid = Some(v),
            ("tag", SfValue::Text(v)) => tag = Some(v),
            ("created", SfValue::Integer(n)) => created = Some(n),
            ("expires", SfValue::Integer(n)) => expires = Some(n),
            ("keyid" | "tag" | "created" | "expires", _) => return None,
            _ => {}
        }
    }
    Some(SignatureInput {
        label,
        components: comps,
        keyid,
        tag,
        created,
        expires,
    })
}

enum SfValue {
    Text(String),
    Integer(u64),
}

/// A minimal RFC 8941 reader for the one dictionary member parsed above.
struct SfParser<'a> {
    s: &'a [u8],
    i: usize,
}

impl SfParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn expect(&mut self, b: u8) -> Option<()> {
        (self.peek()? == b).then(|| self.i += 1)
    }

    fn skip_spaces(&mut self) {
        while self.peek() == Some(b' ') {
            self.i += 1;
        }
    }

    /// A key or token: starts with a letter or `*`, then `[a-z0-9_.*:/%+-]`.
    fn token(&mut self) -> Option<String> {
        let start = self.i;
        match self.peek()? {
            c if c.is_ascii_alphabetic() || c == b'*' => self.i += 1,
            _ => return None,
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || b"_-.*:/%+!#$&'^`|~".contains(&c) {
                self.i += 1;
            } else {
                break;
            }
        }
        std::str::from_utf8(&self.s[start..self.i]).ok().map(str::to_string)
    }

    fn integer(&mut self) -> Option<u64> {
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        if self.i - start > 15 {
            return None;
        }
        std::str::from_utf8(&self.s[start..self.i]).ok()?.parse().ok()
    }

    /// A quoted string with `\"` and `\\` escapes; printable ASCII only.
    fn quoted(&mut self) -> Option<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => return Some(out),
                b'\\' => {
                    let e = self.peek()?;
                    if e != b'"' && e != b'\\' {
                        return None;
                    }
                    self.i += 1;
                    out.push(e as char);
                }
                0x20..=0x7e => out.push(c as char),
                _ => return None,
            }
        }
    }
}

/// One parsed `Signature-Input` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInput {
    /// The signature label (e.g. `sig1`).
    pub label: String,
    /// Covered components (e.g. `@authority`, `signature-agent`).
    pub components: Vec<String>,
    /// The signing key id (JWK thumbprint per the draft).
    pub keyid: Option<String>,
    /// The tag — `web-bot-auth` for this scheme.
    pub tag: Option<String>,
    /// Creation instant (epoch seconds).
    pub created: Option<u64>,
    /// Expiry instant (epoch seconds).
    pub expires: Option<u64>,
}

impl SignatureInput {
    /// Whether this entry claims the Web Bot Auth scheme: tagged
    /// `web-bot-auth` and covering `@authority` (the minimum the draft
    /// requires for a target-bound signature).
    pub fn is_web_bot_auth(&self) -> bool {
        self.tag.as_deref() == Some("web-bot-auth")
            && self.components.iter().any(|c| c == "@authority")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_verified_needs_all_parts() {
        let c = classify(
            Some("\"https://bot.example\""),
            Some("sig1=(...)"),
            Some("sig1=:xyz:"),
            true,
        );
        assert_eq!(
            c,
            CallerClass::Verified {
                agent: "https://bot.example".into()
            }
        );
        // No signature headers -> declared even if the edge said verified.
        let c = classify(Some("https://bot.example"), None, None, true);
        assert_eq!(
            c,
            CallerClass::Declared {
                agent: "https://bot.example".into()
            }
        );
        // Headers but no verifier verdict -> declared.
        let c = classify(Some("https://bot.example"), Some("i"), Some("s"), false);
        assert_eq!(
            c,
            CallerClass::Declared {
                agent: "https://bot.example".into()
            }
        );
        assert_eq!(classify(None, None, None, true), CallerClass::Anonymous);
    }

    #[test]
    fn parse_signature_input_shape() {
        let v = "sig2=(\"@authority\" \"signature-agent\");created=1735689600;keyid=\"poqkLGiy\";tag=\"web-bot-auth\";expires=1735693200";
        let si = parse_signature_input(v).unwrap();
        assert_eq!(si.label, "sig2");
        assert_eq!(si.components, vec!["@authority", "signature-agent"]);
        assert_eq!(si.keyid.as_deref(), Some("poqkLGiy"));
        assert_eq!(si.tag.as_deref(), Some("web-bot-auth"));
        assert_eq!(si.created, Some(1_735_689_600));
        assert_eq!(si.expires, Some(1_735_693_200));
        assert!(si.is_web_bot_auth());
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_signature_input("").is_none());
        assert!(parse_signature_input("no-parens").is_none());
    }

    #[test]
    fn later_dictionary_members_cannot_lend_parameters_to_the_first() {
        let smuggled = r#"sig1=("@authority");created=1;expires=2;tag="other", sig2=();keyid="trusted";tag="web-bot-auth";expires=9999999999"#;
        let s = parse_signature_input(smuggled).unwrap();
        assert_eq!(s.label, "sig1");
        assert_eq!(s.tag.as_deref(), Some("other"));
        assert_eq!(s.keyid, None);
        assert_eq!(s.expires, Some(2));
        assert!(!s.is_web_bot_auth());
        // A first member that is not an inner list does not borrow the next one's.
        assert!(parse_signature_input(r#"sig1=1, sig2=("@authority");tag="web-bot-auth""#).is_none());
        // A ';' inside a quoted value is not a parameter separator.
        let q = parse_signature_input(r#"sig1=("@authority");keyid="a;tag=web-bot-auth""#).unwrap();
        assert_eq!(q.keyid.as_deref(), Some("a;tag=web-bot-auth"));
        assert_eq!(q.tag, None);
        // The ordinary shape still parses.
        let ok = parse_signature_input(r#"sig2=("@authority" "signature-agent");created=1735689600;keyid="k1";tag="web-bot-auth""#).unwrap();
        assert!(ok.is_web_bot_auth());
        assert_eq!(ok.created, Some(1735689600));
        // An empty quoted agent declares nothing.
        assert_eq!(classify(Some("\"\""), Some("sig1=()"), Some("sig1=:x:"), true), CallerClass::Anonymous);
    }
}
