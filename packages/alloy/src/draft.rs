//! Draft mode: previewing unpublished content without publishing the switch.
//!
//! Next.js's `draftMode()` sets a bypass cookie whose VALUE is secret, so
//! only a caller who obtained it through an authenticated enable route can
//! see draft content. Alloy keeps that shape with the platform's own
//! primitives: the cookie value is an HMAC over the app's BUILD string,
//! keyed by an app-supplied secret (`ctx.secret()` is where such a key
//! lives).
//!
//! # Why the MAC covers the build
//!
//! A random token would need server-side storage to verify; a MAC verifies
//! from the key alone, which matters on a platform whose only storage is
//! the planes. Binding it to the BUILD string means every deploy rotates
//! every outstanding draft cookie for free — a preview link pasted into a
//! chat stops working when the content it previewed is no longer what
//! ships, instead of living as a permanent bypass.
//!
//! # Verification is server-side only
//!
//! The client half (`alloy-next`'s `draftMode()`) reports only the cookie's
//! PRESENCE. Presence is not authority: the server recomputes the MAC on
//! every request, so a forged cookie changes what the browser believes and
//! nothing about what the server serves.

use ferrite_app::IngressRequest;

/// The draft-mode cookie name, shared verbatim with the client adapter.
///
/// `__Host-` makes the browser accept it only with `Secure`, `Path=/` and no
/// `Domain`, so a sibling subdomain or a plain-HTTP response cannot plant a
/// shadowing copy.
pub const COOKIE_NAME: &str = "__Host-alloy_draft";

/// The shortest key draft mode accepts. An empty or short key would let
/// anyone who reads the public BUILD string mint a valid cookie.
pub const MIN_KEY_LEN: usize = 16;

/// The label that binds the MAC to draft mode, so a draft cookie is never
/// the same bytes as another HMAC the application derives from the same
/// secret over the same BUILD string.
const DRAFT_LABEL: &[u8] = b"ferrite-alloy/v1/draft-cookie";

/// Whether this request carries a VALID draft cookie.
///
/// The comparison is constant-time. A byte-by-byte early exit would let a
/// caller measure how much of a guessed MAC was right, and a MAC that can
/// be guessed byte-wise is no MAC at all.
pub fn is_enabled(req: &IngressRequest, key: &[u8], build: &str) -> bool {
    let Some(presented) = cookie_value(req, COOKIE_NAME) else {
        return false;
    };
    let Some(expected) = mac_hex(key, build) else {
        return false;
    };
    crate::crypto::constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

/// The `Set-Cookie` value that enables draft mode.
///
/// `HttpOnly` because a script that can read the cookie can exfiltrate it,
/// and no script has any use for the value; `SameSite=Lax` so a cross-site
/// POST cannot ride an existing draft session; `Path=/` because draft mode
/// is a property of the viewer, not of one route; `Secure` because the
/// value is a bearer secret.
///
/// A key shorter than [`MIN_KEY_LEN`] or an empty build mints an empty,
/// expired cookie that never verifies, rather than a forgeable one.
pub fn enable_cookie(key: &[u8], build: &str) -> String {
    match mac_hex(key, build) {
        Some(mac) => format!("{COOKIE_NAME}={mac}; Path=/; Secure; HttpOnly; SameSite=Lax"),
        None => disable_cookie(),
    }
}

/// The `Set-Cookie` value that disables draft mode.
///
/// `Max-Age=0` makes the browser delete the cookie immediately; the value
/// is emptied as well so a client that ignores the age holds nothing that
/// verifies.
pub fn disable_cookie() -> String {
    format!("{COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// The hex MAC a valid cookie carries for `build` under `key`.
///
/// `None` for a key too short to be secret or an empty build. The MAC is
/// taken under a subkey derived with [`DRAFT_LABEL`].
fn mac_hex(key: &[u8], build: &str) -> Option<String> {
    if key.len() < MIN_KEY_LEN || build.is_empty() {
        return None;
    }
    let subkey = ferrite_app::crypto::hmac_sha256(key, DRAFT_LABEL);
    Some(crate::crypto::hex_encode(&ferrite_app::crypto::hmac_sha256(
        &subkey,
        build.as_bytes(),
    )))
}

/// The value of `name` in the request's `cookie` header, when present.
///
/// A cookie header is `k=v; k2=v2` pairs. The NAME match is exact and the
/// split is on the first `=` only, so a value containing `=` survives and
/// a cookie named `x__alloy_draft` cannot answer for the real one. Two
/// occurrences with different values are ambiguous and answer `None`.
fn cookie_value<'a>(req: &'a IngressRequest, name: &str) -> Option<&'a str> {
    let mut found: Option<&'a str> = None;
    for (header_name, header) in &req.headers {
        if !header_name.eq_ignore_ascii_case("cookie") {
            continue;
        }
        for pair in header.split(';') {
            let pair = pair.trim();
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            if k.trim() == name {
                let v = v.trim();
                match found {
                    Some(prev) if prev != v => return None,
                    _ => found = Some(v),
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"a-32-byte-app-secret-goes-here!!";
    const BUILD: &str = "app-build-7";

    fn with_cookie(cookie: &str) -> IngressRequest {
        let mut req = ferrite_app_test::ingress::get("/");
        req.headers.push(("cookie".into(), cookie.into()));
        req
    }

    fn valid_value() -> String {
        enable_cookie(KEY, BUILD)
            .split_once('=')
            .expect("the cookie has a value")
            .1
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    #[test]
    fn a_cookie_minted_by_enable_verifies() {
        let req = with_cookie(&format!("{COOKIE_NAME}={}", valid_value()));
        assert!(is_enabled(&req, KEY, BUILD));
    }

    #[test]
    fn a_request_without_the_cookie_is_not_in_draft_mode() {
        assert!(!is_enabled(
            &ferrite_app_test::ingress::get("/"),
            KEY,
            BUILD
        ));
        // A cookie header naming other cookies is equally not draft mode.
        let req = with_cookie("session=abc; theme=dark");
        assert!(!is_enabled(&req, KEY, BUILD));
    }

    #[test]
    fn a_forged_mac_is_refused() {
        // The forger knows the cookie name, the build string and the MAC's
        // length — everything but the key — and still cannot mint a value.
        for forged in [
            "deadbeef".repeat(8),             // right length, wrong bytes
            String::new(),                    // empty
            "0".into(),                       // short
            valid_value() + "00",             // valid prefix, extended
            valid_value().to_uppercase(),     // case-mangled hex
            mac_hex(b"the-wrong-key-0000", BUILD).unwrap(), // wrong key
        ] {
            let req = with_cookie(&format!("{COOKIE_NAME}={forged}"));
            assert!(!is_enabled(&req, KEY, BUILD), "'{forged}' verified");
        }
    }

    #[test]
    fn an_empty_or_short_key_never_enables_draft_mode() {
        // finding_de36da4a9558fd89: an empty key would make the MAC public.
        let raw = crate::crypto::hex_encode(&ferrite_app::crypto::hmac_sha256(b"", BUILD.as_bytes()));
        let req = with_cookie(&format!("{COOKIE_NAME}={raw}"));
        assert!(!is_enabled(&req, b"", BUILD));
        assert!(!is_enabled(&req, b"short", BUILD));
        assert!(enable_cookie(b"", BUILD).contains("Max-Age=0"));
        // The MAC is domain-separated from a plain HMAC over BUILD.
        let plain = crate::crypto::hex_encode(&ferrite_app::crypto::hmac_sha256(KEY, BUILD.as_bytes()));
        assert_ne!(valid_value(), plain);
    }

    #[test]
    fn a_duplicate_draft_cookie_is_ambiguous() {
        // finding_696d593031539334
        let value = valid_value();
        let req = with_cookie(&format!("{COOKIE_NAME}=deadbeef; {COOKIE_NAME}={value}"));
        assert!(!is_enabled(&req, KEY, BUILD));
        let req = with_cookie(&format!("{COOKIE_NAME}={value}; {COOKIE_NAME}={value}"));
        assert!(is_enabled(&req, KEY, BUILD));
    }

    #[test]
    fn a_deploy_rotates_every_outstanding_cookie() {
        // The MAC covers the BUILD string, so a cookie minted for one build
        // stops verifying on the next — a preview link cannot outlive the
        // content it previewed.
        let req = with_cookie(&format!("{COOKIE_NAME}={}", valid_value()));
        assert!(is_enabled(&req, KEY, BUILD));
        assert!(!is_enabled(&req, KEY, "app-build-8"));
    }

    #[test]
    fn a_lookalike_cookie_name_cannot_answer_for_the_real_one() {
        let value = valid_value();
        // A prefix-extended name, and the real value hidden in another
        // cookie's VALUE, must both miss.
        let req = with_cookie(&format!(
            "x{COOKIE_NAME}={value}; other={COOKIE_NAME}={value}"
        ));
        assert!(!is_enabled(&req, KEY, BUILD));
        // …while the real name still matches when surrounded by neighbours
        // or preceded by a bare flag segment without `=`.
        let req = with_cookie(&format!("flag; a=1; {COOKIE_NAME}={value}; b=2"));
        assert!(is_enabled(&req, KEY, BUILD));
    }

    #[test]
    fn the_cookie_attributes_scope_and_contain_it() {
        let enable = enable_cookie(KEY, BUILD);
        assert!(enable.starts_with(&format!("{COOKIE_NAME}=")));
        // HttpOnly: no script can read it. SameSite=Lax: a cross-site POST
        // cannot ride it. Path=/: draft mode is per-viewer, not per-route.
        assert!(enable.contains("; HttpOnly"));
        assert!(enable.contains("; SameSite=Lax"));
        assert!(enable.contains("; Path=/"));
        assert!(enable.contains("; Secure"));
        assert!(COOKIE_NAME.starts_with("__Host-"));

        let disable = disable_cookie();
        assert!(disable.starts_with(&format!("{COOKIE_NAME}=;")));
        assert!(disable.contains("; Max-Age=0"), "the cookie must expire");
        assert!(disable.contains("; HttpOnly"));
    }
}
