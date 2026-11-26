//! The typed error surface.
//!
//! Server control flow in Alloy is `Result`, never an exception: a redirect, a
//! not-found, and an authorization refusal are all ordinary return values, so
//! the compiler forces every caller to propagate them and nothing can swallow
//! them by accident. This is the Rust answer to Next.js's thrown `redirect()`
//! and its `unstable_rethrow` escape hatch — neither of which needs to exist
//! here.
//!
//! Every variant renders to an RFC 9457 `application/problem+json` body, which
//! is also what makes a Alloy app score on the agent-readiness checklist
//! without the author writing an error handler.

use ferrite_app::serde::{Deserialize, Serialize};
use ferrite_app::serde_json;
use ferrite_app::IngressReply;
// The attested build's macro gate admits `tracing::warn!` (the reviewed
// path form), not a fully-qualified path.
use ferrite_app::tracing;

/// The framework's result alias.
pub type Result<T, E = AlloyError> = core::result::Result<T, E>;

/// A typed server error, carrying its HTTP semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", tag = "kind", rename_all = "snake_case")]
pub enum AlloyError {
    /// The resource does not exist: renders the route's `not-found` boundary.
    NotFound,
    /// The caller is authenticated but not permitted.
    Forbidden,
    /// The caller is not authenticated.
    Unauthorized,
    /// The request itself is malformed. `fields` names the offending inputs,
    /// which is what lets a generated form surface per-field messages.
    BadRequest {
        /// A human-readable summary.
        message: String,
        /// Field path → message.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fields: Vec<(String, String)>,
    },
    /// An optimistic-concurrency or state conflict; the caller may re-read
    /// and retry.
    Conflict {
        /// A human-readable summary.
        message: String,
    },
    /// The caller is over a declared rate or spend bound.
    TooManyRequests {
        /// Seconds until a retry may succeed.
        retry_after_secs: u64,
    },
    /// An unexpected server fault. The digest is safe to show a user and to
    /// correlate with a log line; the underlying message never crosses the
    /// boundary.
    Internal {
        /// A stable digest of the underlying cause.
        digest: String,
    },
    /// A redirect, as a value rather than a thrown exception.
    Redirect {
        /// The `Location` header to emit.
        location: String,
        /// 308 when true, 307 otherwise.
        permanent: bool,
    },
    /// A complete reply that some other component already built, sent as it
    /// is instead of being rendered as a problem document.
    ///
    /// This is how a gate that owns its refusals passes them through a seam
    /// that returns `Result`, above all [`AlloyApp::admit`](crate::alloy::app::AlloyApp::admit):
    /// the `auth` package's `Auth::gate` answers an anonymous page load with
    /// a 303 to its sign-in page and a failed CSRF check with a 403 that names
    /// the condition, and `.map_err(AlloyError::reply)?` delivers exactly
    /// that. The runtime replaces the reply's correlation id with the
    /// request's and changes nothing else.
    Reply {
        /// The reply to send.
        reply: Box<IngressReply>,
    },
}

impl AlloyError {
    /// A bad-request error with no field detail.
    pub fn bad_request(message: impl Into<String>) -> Self {
        AlloyError::BadRequest {
            message: message.into(),
            fields: Vec::new(),
        }
    }

    /// A conflict error.
    pub fn conflict(message: impl Into<String>) -> Self {
        AlloyError::Conflict {
            message: message.into(),
        }
    }

    /// A forbidden refusal, with the reason kept server-side.
    ///
    /// The reason reaches the log, never the problem document: a 403's body
    /// is read by exactly the caller whose request was refused, and telling
    /// a forger which check caught them is a gift only they can use. The
    /// variant itself stays a unit — `alloy-auth` and the applications match
    /// on `AlloyError::Forbidden` as a pattern, so the shape is load-bearing.
    pub fn forbidden(reason: impl AsRef<str>) -> Self {
        tracing::warn!(
            target: "alloy::error",
            reason = %reason.as_ref(),
            "a request was refused as forbidden"
        );
        AlloyError::Forbidden
    }

    /// An internal error whose digest is derived from `cause`, so the same
    /// fault always reports the same digest without ever exposing the text.
    pub fn internal(cause: impl AsRef<str>) -> Self {
        let d = ferrite_app::crypto::sha256(cause.as_ref().as_bytes());
        let mut digest = String::with_capacity(16);
        for byte in d.iter().take(8) {
            digest.push_str(&format!("{byte:02x}"));
        }
        AlloyError::Internal { digest }
    }

    /// A temporary redirect (307).
    pub fn redirect(location: impl Into<String>) -> Self {
        AlloyError::Redirect {
            location: location.into(),
            permanent: false,
        }
    }

    /// A prepared reply, sent as it is (see [`AlloyError::Reply`]). Written to
    /// fit `map_err`: `auth.gate(req, now).await.map_err(AlloyError::reply)?`.
    pub fn reply(reply: IngressReply) -> Self {
        AlloyError::Reply {
            reply: Box::new(reply),
        }
    }

    /// A permanent redirect (308).
    pub fn permanent_redirect(location: impl Into<String>) -> Self {
        AlloyError::Redirect {
            location: location.into(),
            permanent: true,
        }
    }

    /// The HTTP status this error serves as.
    pub fn status(&self) -> u16 {
        match self {
            AlloyError::NotFound => 404,
            AlloyError::Forbidden => 403,
            AlloyError::Unauthorized => 401,
            AlloyError::BadRequest { .. } => 400,
            AlloyError::Conflict { .. } => 409,
            AlloyError::TooManyRequests { .. } => 429,
            AlloyError::Internal { .. } => 500,
            AlloyError::Redirect { permanent, .. } => {
                if *permanent {
                    308
                } else {
                    307
                }
            }
            AlloyError::Reply { reply } => reply.status,
        }
    }

    /// The stable machine-readable type slug (the RFC 9457 `type` tail).
    pub fn slug(&self) -> &'static str {
        match self {
            AlloyError::NotFound => "not-found",
            AlloyError::Forbidden => "forbidden",
            AlloyError::Unauthorized => "unauthorized",
            AlloyError::BadRequest { .. } => "bad-request",
            AlloyError::Conflict { .. } => "conflict",
            AlloyError::TooManyRequests { .. } => "too-many-requests",
            AlloyError::Internal { .. } => "internal",
            AlloyError::Redirect { .. } => "redirect",
            AlloyError::Reply { .. } => "reply",
        }
    }

    /// Whether a client may retry this request unchanged.
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            AlloyError::Conflict { .. } | AlloyError::TooManyRequests { .. }
        )
    }

    /// Render as an RFC 9457 problem document.
    pub fn problem_json(&self) -> serde_json::Value {
        let mut doc = serde_json::json!({
            "type": format!("urn:ferrite:problem:{}", self.slug()),
            "title": self.title(),
            "status": self.status(),
            "retryable": self.retryable(),
        });
        let obj = doc.as_object_mut().expect("problem document is an object");
        match self {
            AlloyError::BadRequest { message, fields } => {
                obj.insert("detail".into(), serde_json::Value::String(message.clone()));
                if !fields.is_empty() {
                    let errs: Vec<serde_json::Value> = fields
                        .iter()
                        .map(|(name, detail)| serde_json::json!({ "name": name, "reason": detail }))
                        .collect();
                    obj.insert("errors".into(), serde_json::Value::Array(errs));
                }
            }
            AlloyError::Conflict { message } => {
                obj.insert("detail".into(), serde_json::Value::String(message.clone()));
            }
            AlloyError::TooManyRequests { retry_after_secs } => {
                obj.insert(
                    "retry_after".into(),
                    serde_json::Value::from(*retry_after_secs),
                );
            }
            AlloyError::Internal { digest } => {
                obj.insert("digest".into(), serde_json::Value::String(digest.clone()));
            }
            AlloyError::Redirect { location, .. } => {
                obj.insert(
                    "location".into(),
                    serde_json::Value::String(location.clone()),
                );
            }
            _ => {}
        }
        doc
    }

    fn title(&self) -> &'static str {
        match self {
            AlloyError::NotFound => "Not Found",
            AlloyError::Forbidden => "Forbidden",
            AlloyError::Unauthorized => "Unauthorized",
            AlloyError::BadRequest { .. } => "Bad Request",
            AlloyError::Conflict { .. } => "Conflict",
            AlloyError::TooManyRequests { .. } => "Too Many Requests",
            AlloyError::Internal { .. } => "Internal Server Error",
            AlloyError::Redirect { .. } => "Redirect",
            AlloyError::Reply { .. } => "Reply",
        }
    }
}

impl core::fmt::Display for AlloyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} ({})", self.title(), self.status())
    }
}

impl From<std::io::Error> for AlloyError {
    /// A plane error is an internal fault: the cause is digested, never
    /// forwarded, so a store error message cannot reach a browser.
    fn from(e: std::io::Error) -> Self {
        AlloyError::internal(e.to_string())
    }
}

/// The error half of an action's typed result. The generator emits this as a
/// discriminated union on the TypeScript side, so a client `switch` over the
/// `kind` field is exhaustive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct ActionError {
    /// The typed failure.
    pub error: AlloyError,
    /// The action that produced it.
    pub action: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_match_their_semantics() {
        assert_eq!(AlloyError::NotFound.status(), 404);
        assert_eq!(AlloyError::Unauthorized.status(), 401);
        assert_eq!(AlloyError::Forbidden.status(), 403);
        assert_eq!(AlloyError::bad_request("x").status(), 400);
        assert_eq!(AlloyError::conflict("x").status(), 409);
        assert_eq!(AlloyError::redirect("/a").status(), 307);
        assert_eq!(AlloyError::permanent_redirect("/a").status(), 308);
    }

    #[test]
    fn an_internal_error_never_carries_its_cause() {
        let e = AlloyError::internal("connection refused to 10.0.0.7 with token sk-secret");
        let rendered = e.problem_json().to_string();
        assert!(!rendered.contains("sk-secret"));
        assert!(!rendered.contains("10.0.0.7"));
        // …but it is stable, so a log line can be correlated with it.
        let again = AlloyError::internal("connection refused to 10.0.0.7 with token sk-secret");
        assert_eq!(e, again);
    }

    #[test]
    fn a_plane_error_digests_rather_than_forwards() {
        let io = std::io::Error::other("ape group 'social' unreachable");
        let e: AlloyError = io.into();
        assert_eq!(e.status(), 500);
        assert!(!e.problem_json().to_string().contains("unreachable"));
    }

    #[test]
    fn bad_request_carries_field_detail() {
        let e = AlloyError::BadRequest {
            message: "invalid booking".into(),
            fields: vec![("starts_at".into(), "must be in the future".into())],
        };
        let doc = e.problem_json();
        assert_eq!(doc["status"], 400);
        assert_eq!(doc["errors"][0]["name"], "starts_at");
        assert_eq!(doc["errors"][0]["reason"], "must be in the future");
    }

    #[test]
    fn problem_documents_are_rfc9457_shaped() {
        let doc = AlloyError::NotFound.problem_json();
        assert_eq!(doc["type"], "urn:ferrite:problem:not-found");
        assert_eq!(doc["title"], "Not Found");
        assert_eq!(doc["status"], 404);
        assert_eq!(doc["retryable"], false);
    }

    #[test]
    fn a_prepared_reply_keeps_its_own_status_and_is_not_retryable() {
        let mut prepared = IngressReply::new("elsewhere", 303, Vec::new());
        prepared
            .headers
            .push(("location".into(), "/auth/sign-in?return_to=%2Faccount".into()));
        let e = AlloyError::reply(prepared.clone());
        assert_eq!(e.status(), 303);
        assert_eq!(e.slug(), "reply");
        assert!(!e.retryable());
        assert_eq!(e, AlloyError::Reply { reply: Box::new(prepared) });
    }

    #[test]
    fn only_conflict_and_rate_limits_are_retryable() {
        assert!(AlloyError::conflict("stale").retryable());
        assert!(AlloyError::TooManyRequests {
            retry_after_secs: 3
        }
        .retryable());
        assert!(!AlloyError::NotFound.retryable());
        assert!(!AlloyError::internal("x").retryable());
    }
}
