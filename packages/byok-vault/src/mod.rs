//! Encrypted per-user BYOK key vault and Ferrite AI Gateway verification helpers.
//!
//! All provider key verification and model inference stays routed through the
//! Ferrite AI Gateway (`ai.ferrite.cloud`) using per-request BYOK headers so
//! constrained apps never declare direct provider egress and never fall back
//! to platform credentials.

use std::time::Duration;

use ferrite_app::{
    client::StoreClusterClient,
    crypto::{base64url_decode, base64url_encode},
    rt,
    serde::{Deserialize, Serialize},
    serde_json::{self, json, Value},
    AppContext, EgressHeader, EgressHttpMethod, EgressOutcome,
};

use crate::crypto::{constant_time_eq, hex_encode, hmac_sha256, random_bytes, sha256};

/// Header carrying a per-request BYOK provider key to the Ferrite AI Gateway.
pub const HEADER_PROVIDER_KEY: &str = "x-ferrite-provider-key";
/// Header binding `x-ferrite-provider-key` to one specific provider so cross-provider
/// routing or route overrides can never send a key to the wrong provider.
pub const HEADER_PROVIDER_KEY_PROVIDER: &str = "x-ferrite-provider-key-provider";
/// Header instructing the Ferrite AI Gateway never to fall back to platform
/// (or account-stored) provider keys.
pub const HEADER_BYOK_ONLY: &str = "x-ferrite-byok-only";
/// Strict mode value: only the per-request key on this call may be used.
pub const BYOK_ONLY_REQUEST: &str = "request";
/// Gateway endpoint that verifies a user-supplied provider API key.
pub const VERIFY_PATH: &str = "/gw/v1/byok/verify";

const MAX_KEY_BYTES: usize = 1024;
const NONCE_BYTES: usize = 24;
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_VERIFY_REPLY_BYTES: usize = 256 * 1024;
const MASTER_DOMAIN: &[u8] = b"ferrite-byok-vault/master/v1";
const KEY_ID_DOMAIN: &[u8] = b"ferrite-byok-vault/key-id/v1";
const AEAD_DOMAIN: &[u8] = b"ferrite-byok-vault/aead/v1";

/// Providers supported for per-user BYOK through the Ferrite AI Gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Provider {
    Anthropic,
    OpenAi,
    Google,
}

impl Provider {
    pub const ALL: [Provider; 3] = [Provider::Anthropic, Provider::OpenAi, Provider::Google];

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "anthropic" => Some(Self::Anthropic),
            "openai" => Some(Self::OpenAi),
            "google" | "gemini" => Some(Self::Google),
            _ => None,
        }
    }

    pub const fn id(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
            Self::Google => "google",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::OpenAi => "OpenAI",
            Self::Google => "Gemini",
        }
    }

    pub const fn placeholder(self) -> &'static str {
        match self {
            Self::Anthropic => "sk-ant-...",
            Self::OpenAi => "sk-...",
            Self::Google => "AIza...",
        }
    }
}

/// Headers to attach to an outbound AI Gateway inference call using a user's
/// decrypted provider key. Forces strict per-request BYOK with zero fallback.
pub fn request_headers(api_key: &str) -> Vec<EgressHeader> {
    vec![
        EgressHeader {
            name: HEADER_PROVIDER_KEY.to_owned(),
            value: api_key.to_owned(),
        },
        strict_request_only_header(),
    ]
}

/// Like [`request_headers`], also binding the key to `provider` via
/// `x-ferrite-provider-key-provider` so the AI Gateway refuses dispatch if a
/// route ever resolves to a different provider.
pub fn request_headers_for_provider(provider: Provider, api_key: &str) -> Vec<EgressHeader> {
    vec![
        EgressHeader {
            name: HEADER_PROVIDER_KEY.to_owned(),
            value: api_key.to_owned(),
        },
        EgressHeader {
            name: HEADER_PROVIDER_KEY_PROVIDER.to_owned(),
            value: provider.id().to_owned(),
        },
        strict_request_only_header(),
    ]
}

/// Header instructing the AI Gateway to require a per-request provider key and
/// never fall back to account-stored BYOK or platform credentials.
pub fn strict_request_only_header() -> EgressHeader {
    EgressHeader {
        name: HEADER_BYOK_ONLY.to_owned(),
        value: BYOK_ONLY_REQUEST.to_owned(),
    }
}

/// Errors produced by key validation, sealing, or store I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    InvalidInput(String),
    Unconfigured(String),
    CorruptRecord,
    StoreUnavailable,
    GatewayUnavailable(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(msg) => f.write_str(msg),
            Self::Unconfigured(msg) => f.write_str(msg),
            Self::CorruptRecord => f.write_str("Stored API key record could not be verified"),
            Self::StoreUnavailable => f.write_str("API key store is temporarily unavailable"),
            Self::GatewayUnavailable(msg) => f.write_str(msg),
        }
    }
}

/// Validate a raw user-submitted API key before sending it to the AI Gateway
/// or sealing it in storage. Rejects control characters, spaces, non-ASCII,
/// empty input, and oversize values.
pub fn validate_key_shape(raw: &str) -> Result<String, VaultError> {
    if raw.chars().any(char::is_control) {
        return Err(VaultError::InvalidInput(
            "API key must be printable ASCII with no line breaks or control characters".into(),
        ));
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(VaultError::InvalidInput("API key is required".into()));
    }
    if trimmed.len() > MAX_KEY_BYTES {
        return Err(VaultError::InvalidInput(
            "API key exceeds the 1024-byte limit".into(),
        ));
    }
    if !trimmed
        .bytes()
        .all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(VaultError::InvalidInput(
            "API key must be printable ASCII with no spaces".into(),
        ));
    }
    Ok(trimmed.to_owned())
}

/// Return a non-sensitive masked display hint for a stored key (never the key).
pub fn mask_hint(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    if chars.len() < 10 {
        return "••••••••".to_owned();
    }
    let prefix_len = 4.min(chars.len() / 3);
    let prefix: String = chars[..prefix_len].iter().collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    format!("{prefix}…{suffix}")
}

/// Public, non-sensitive status of one provider slot for a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde", rename_all = "camelCase")]
pub struct ProviderKeyStatus {
    pub provider: String,
    pub label: String,
    pub placeholder: String,
    pub configured: bool,
    pub valid: bool,
    pub hint: Option<String>,
    pub validated_at_ms: Option<u64>,
    pub models: Vec<String>,
    pub error: Option<String>,
}

/// Result returned by `POST /gw/v1/byok/verify` on the Ferrite AI Gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOutcome {
    pub valid: bool,
    pub provider: Provider,
    pub models: Vec<String>,
    pub code: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
struct StoredRecord {
    version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    nonce: String,
    ciphertext: String,
    mac: String,
    hint: String,
    valid: bool,
    validated_at_ms: u64,
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    last_error: Option<String>,
}

/// Verify a user-supplied API key through the Ferrite AI Gateway's
/// `POST /gw/v1/byok/verify` endpoint. Never calls providers directly.
pub async fn verify_via_gateway(
    ctx: &AppContext,
    egress_handle: &str,
    gateway_origin: &str,
    gateway_key: &str,
    provider: Provider,
    api_key: &str,
) -> Result<VerifyOutcome, VaultError> {
    let api_key = validate_key_shape(api_key)?;
    let origin = gateway_origin.trim().trim_end_matches('/');
    if !origin.starts_with("https://") && !origin.starts_with("http://127.0.0.1:") {
        return Err(VaultError::Unconfigured(
            "AI Gateway origin is not configured".into(),
        ));
    }
    if gateway_key.trim().is_empty() {
        return Err(VaultError::Unconfigured(
            "AI Gateway credential is not configured".into(),
        ));
    }
    let url = format!("{origin}{VERIFY_PATH}");
    let body = serde_json::to_vec(&json!({
        "provider": provider.id(),
        "api_key": api_key,
    }))
    .map_err(|_| VaultError::InvalidInput("Could not encode verification request".into()))?;
    let headers = [
        EgressHeader {
            name: "content-type".into(),
            value: "application/json".into(),
        },
        EgressHeader {
            name: "accept".into(),
            value: "application/json".into(),
        },
        EgressHeader {
            name: "authorization".into(),
            value: format!("Bearer {}", gateway_key.trim()),
        },
    ];
    let mut egress = ctx
        .egress(egress_handle)
        .map_err(|_| VaultError::GatewayUnavailable("AI Gateway egress is unavailable".into()))?;
    let outcome = rt::time::timeout(
        VERIFY_TIMEOUT,
        egress.deliver_http(EgressHttpMethod::Post, &url, &headers, &body),
    )
    .await
    .map_err(|_| {
        VaultError::GatewayUnavailable(
            "Timed out waiting for the AI Gateway to verify this API key".into(),
        )
    })?
    .map_err(|_| {
        VaultError::GatewayUnavailable("Could not reach the AI Gateway to verify this key".into())
    })?;

    match outcome {
        EgressOutcome::Denied { .. } => Err(VaultError::GatewayUnavailable(
            "AI Gateway verification egress was denied".into(),
        )),
        EgressOutcome::Delivered { status, body } => {
            if body.len() > MAX_VERIFY_REPLY_BYTES {
                return Err(VaultError::GatewayUnavailable(
                    "AI Gateway returned an oversized verification response".into(),
                ));
            }
            let parsed: Value = serde_json::from_slice(&body).map_err(|_| {
                VaultError::GatewayUnavailable(format!(
                    "AI Gateway verification returned an unreadable response (HTTP {status})"
                ))
            })?;
            if status != 200 {
                let message = parsed
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("AI Gateway rejected the key verification request");
                if status == 400 {
                    return Err(VaultError::InvalidInput(message.to_owned()));
                }
                return Err(VaultError::GatewayUnavailable(format!(
                    "{message} (HTTP {status})"
                )));
            }
            let valid = parsed.get("valid").and_then(Value::as_bool).unwrap_or(false);
            let models = parsed
                .get("models")
                .and_then(Value::as_array)
                .map(|rows| {
                    rows.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let code = parsed
                .get("code")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let error = parsed
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_owned);
            Ok(VerifyOutcome {
                valid,
                provider,
                models,
                code,
                error,
            })
        }
    }
}

/// Encrypted per-owner BYOK vault backed by a Ferrite `StoreClusterClient`.
pub struct ByokVault {
    store: StoreClusterClient,
    master: [u8; 32],
    key_id: String,
}

impl ByokVault {
    pub fn new(store: StoreClusterClient, app_secret: &str) -> Result<Self, VaultError> {
        if app_secret.len() < 16 {
            return Err(VaultError::Unconfigured(
                "Vault sealing key must be at least 16 bytes".into(),
            ));
        }
        let master = hmac_sha256(app_secret.as_bytes(), MASTER_DOMAIN);
        let key_id = hex_encode(&hmac_sha256(&master, KEY_ID_DOMAIN))[..16].to_owned();
        Ok(Self {
            store,
            master,
            key_id,
        })
    }

    fn row_key(owner: &str, provider: Provider) -> String {
        format!(
            "byok-vault/v1/{}/{}",
            hex_encode(&sha256(owner.as_bytes())),
            provider.id()
        )
    }

    fn aad(owner: &str, provider: Provider) -> Vec<u8> {
        format!("byok-vault/v1\x1f{owner}\x1f{}", provider.id()).into_bytes()
    }

    /// Encrypt and persist a verified provider key for `owner`.
    pub async fn save_verified(
        &mut self,
        owner: &str,
        provider: Provider,
        api_key: &str,
        models: Vec<String>,
        now_ms: u64,
    ) -> Result<ProviderKeyStatus, VaultError> {
        let cleaned = validate_key_shape(api_key)?;
        let aad = Self::aad(owner, provider);
        let (nonce, ciphertext, mac) = seal(&self.master, &aad, cleaned.as_bytes())?;
        let hint = mask_hint(&cleaned);
        let record = StoredRecord {
            version: 1,
            key_id: Some(self.key_id.clone()),
            nonce: base64url_encode(&nonce),
            ciphertext: base64url_encode(&ciphertext),
            mac: base64url_encode(&mac),
            hint: hint.clone(),
            valid: true,
            validated_at_ms: now_ms,
            models: models.clone(),
            last_error: None,
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| VaultError::StoreUnavailable)?;
        let key = Self::row_key(owner, provider);
        self.store
            .put(key.as_bytes(), &bytes)
            .await
            .map_err(|_| VaultError::StoreUnavailable)?;
        Ok(ProviderKeyStatus {
            provider: provider.id().to_owned(),
            label: provider.label().to_owned(),
            placeholder: provider.placeholder().to_owned(),
            configured: true,
            valid: true,
            hint: Some(hint),
            validated_at_ms: Some(now_ms),
            models,
            error: None,
        })
    }

    /// Update validation metadata for an already stored key (e.g. after re-verify).
    pub async fn record_revalidation(
        &mut self,
        owner: &str,
        provider: Provider,
        valid: bool,
        models: Vec<String>,
        error: Option<String>,
        now_ms: u64,
    ) -> Result<Option<ProviderKeyStatus>, VaultError> {
        self.record_revalidation_if_version(owner, provider, None, valid, models, error, now_ms)
            .await
    }

    /// CAS-guarded revalidation update so a stale in-flight revalidation never
    /// overwrites a newer key saved concurrently.
    pub async fn record_revalidation_if_version(
        &mut self,
        owner: &str,
        provider: Provider,
        expected_version: Option<u64>,
        valid: bool,
        models: Vec<String>,
        error: Option<String>,
        now_ms: u64,
    ) -> Result<Option<ProviderKeyStatus>, VaultError> {
        let key = Self::row_key(owner, provider);
        let Some((raw, current_version)) = self
            .store
            .get_versioned(key.as_bytes())
            .await
            .map_err(|_| VaultError::StoreUnavailable)?
        else {
            return Ok(None);
        };
        let mut record: StoredRecord =
            serde_json::from_slice(&raw).map_err(|_| VaultError::CorruptRecord)?;
        if record.version != 1 {
            return Err(VaultError::CorruptRecord);
        }
        if let Some(expected) = expected_version {
            if current_version != expected {
                return Ok(Some(status_from_record(provider, &record)));
            }
        }
        record.valid = valid;
        record.validated_at_ms = now_ms;
        if valid {
            record.models = models;
            record.last_error = None;
        } else {
            record.models.clear();
            record.last_error = error;
        }
        let bytes = serde_json::to_vec(&record).map_err(|_| VaultError::StoreUnavailable)?;
        let committed = self
            .store
            .put_if_version(key.as_bytes(), &bytes, Some(current_version))
            .await
            .map_err(|_| VaultError::StoreUnavailable)?;
        if committed.is_err() {
            return match self
                .store
                .get(key.as_bytes())
                .await
                .map_err(|_| VaultError::StoreUnavailable)?
            {
                Some(newer) => {
                    let newer_rec: StoredRecord =
                        serde_json::from_slice(&newer).map_err(|_| VaultError::CorruptRecord)?;
                    Ok(Some(status_from_record(provider, &newer_rec)))
                }
                None => Ok(None),
            };
        }
        Ok(Some(status_from_record(provider, &record)))
    }

    /// Decrypt and return `owner`'s stored API key for `provider` (for server-side
    /// forwarding to the AI Gateway only — never return this to a browser).
    pub async fn read_secret(
        &mut self,
        owner: &str,
        provider: Provider,
    ) -> Result<Option<(String, bool)>, VaultError> {
        Ok(self
            .read_secret_versioned(owner, provider)
            .await?
            .map(|(secret, valid, _)| (secret, valid)))
    }

    /// Like [`Self::read_secret`], also returning the store revision for CAS revalidation.
    pub async fn read_secret_versioned(
        &mut self,
        owner: &str,
        provider: Provider,
    ) -> Result<Option<(String, bool, u64)>, VaultError> {
        let key = Self::row_key(owner, provider);
        let Some((raw, version)) = self
            .store
            .get_versioned(key.as_bytes())
            .await
            .map_err(|_| VaultError::StoreUnavailable)?
        else {
            return Ok(None);
        };
        let record: StoredRecord =
            serde_json::from_slice(&raw).map_err(|_| VaultError::CorruptRecord)?;
        if record.version != 1 {
            return Err(VaultError::CorruptRecord);
        }
        let nonce = base64url_decode(&record.nonce).map_err(|_| VaultError::CorruptRecord)?;
        let ciphertext =
            base64url_decode(&record.ciphertext).map_err(|_| VaultError::CorruptRecord)?;
        let mac = base64url_decode(&record.mac).map_err(|_| VaultError::CorruptRecord)?;
        let aad = Self::aad(owner, provider);
        let plain = open(&self.master, &aad, &nonce, &ciphertext, &mac)
            .ok_or(VaultError::CorruptRecord)?;
        let text = String::from_utf8(plain).map_err(|_| VaultError::CorruptRecord)?;
        let valid_key = validate_key_shape(&text).map_err(|_| VaultError::CorruptRecord)?;
        Ok(Some((valid_key, record.valid, version)))
    }

    /// Remove `owner`'s stored key for `provider`.
    pub async fn delete(&mut self, owner: &str, provider: Provider) -> Result<(), VaultError> {
        let key = Self::row_key(owner, provider);
        self.store
            .delete(key.as_bytes())
            .await
            .map(|_| ())
            .map_err(|_| VaultError::StoreUnavailable)
    }

    /// Return non-sensitive status for every supported provider for `owner`.
    /// Verifies each stored record's key ID and AEAD tag against the active
    /// vault key so a rotated vault key or tampered row surfaces as invalid
    /// rather than falsely showing "Connected".
    pub async fn list_statuses(&mut self, owner: &str) -> Result<Vec<ProviderKeyStatus>, VaultError> {
        let mut out = Vec::with_capacity(Provider::ALL.len());
        for provider in Provider::ALL {
            let key = Self::row_key(owner, provider);
            let status = match self
                .store
                .get(key.as_bytes())
                .await
                .map_err(|_| VaultError::StoreUnavailable)?
            {
                Some(raw) => match serde_json::from_slice::<StoredRecord>(&raw) {
                    Ok(record) if record.version == 1 => {
                        let key_id_matches = record
                            .key_id
                            .as_deref()
                            .is_none_or(|id| constant_time_eq(id.as_bytes(), self.key_id.as_bytes()));
                        let readable = key_id_matches && self.record_is_readable(owner, provider, &record);
                        if readable {
                            status_from_record(provider, &record)
                        } else {
                            ProviderKeyStatus {
                                provider: provider.id().to_owned(),
                                label: provider.label().to_owned(),
                                placeholder: provider.placeholder().to_owned(),
                                configured: true,
                                valid: false,
                                hint: Some(record.hint),
                                validated_at_ms: Some(record.validated_at_ms),
                                models: Vec::new(),
                                error: Some(
                                    "Stored API key cannot be decrypted with the current vault key; save your key again."
                                        .into(),
                                ),
                            }
                        }
                    }
                    _ => ProviderKeyStatus {
                        provider: provider.id().to_owned(),
                        label: provider.label().to_owned(),
                        placeholder: provider.placeholder().to_owned(),
                        configured: true,
                        valid: false,
                        hint: None,
                        validated_at_ms: None,
                        models: Vec::new(),
                        error: Some("Stored key could not be read; save a new key.".into()),
                    },
                },
                None => ProviderKeyStatus {
                    provider: provider.id().to_owned(),
                    label: provider.label().to_owned(),
                    placeholder: provider.placeholder().to_owned(),
                    configured: false,
                    valid: false,
                    hint: None,
                    validated_at_ms: None,
                    models: Vec::new(),
                    error: None,
                },
            };
            out.push(status);
        }
        Ok(out)
    }

    fn record_is_readable(&self, owner: &str, provider: Provider, record: &StoredRecord) -> bool {
        let Ok(nonce) = base64url_decode(&record.nonce) else {
            return false;
        };
        let Ok(ciphertext) = base64url_decode(&record.ciphertext) else {
            return false;
        };
        let Ok(mac) = base64url_decode(&record.mac) else {
            return false;
        };
        let aad = Self::aad(owner, provider);
        open(&self.master, &aad, &nonce, &ciphertext, &mac).is_some()
    }
}

fn status_from_record(provider: Provider, record: &StoredRecord) -> ProviderKeyStatus {
    ProviderKeyStatus {
        provider: provider.id().to_owned(),
        label: provider.label().to_owned(),
        placeholder: provider.placeholder().to_owned(),
        configured: true,
        valid: record.valid,
        hint: Some(record.hint.clone()),
        validated_at_ms: Some(record.validated_at_ms),
        models: if record.valid {
            record.models.clone()
        } else {
            Vec::new()
        },
        error: record.last_error.clone(),
    }
}

fn fresh_nonce() -> Result<[u8; NONCE_BYTES], VaultError> {
    let bytes = random_bytes(NONCE_BYTES).map_err(|_| VaultError::StoreUnavailable)?;
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

fn derive_subkey(master: &[u8; 32], label: &[u8], nonce: &[u8], aad: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(label.len() + nonce.len() + aad.len() + 16);
    input.extend_from_slice(label);
    input.extend_from_slice(&(nonce.len() as u64).to_be_bytes());
    input.extend_from_slice(nonce);
    input.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    input.extend_from_slice(aad);
    hmac_sha256(master, &input)
}

fn xor_keystream(enc_key: &[u8; 32], input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for (counter, chunk) in input.chunks(32).enumerate() {
        let block = hmac_sha256(enc_key, &(counter as u64).to_be_bytes());
        for (byte, mask) in chunk.iter().zip(block.iter()) {
            out.push(byte ^ mask);
        }
    }
    out
}

fn compute_mac(mac_key: &[u8; 32], aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(AEAD_DOMAIN.len() + aad.len() + nonce.len() + ciphertext.len() + 24);
    input.extend_from_slice(AEAD_DOMAIN);
    input.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    input.extend_from_slice(aad);
    input.extend_from_slice(&(nonce.len() as u64).to_be_bytes());
    input.extend_from_slice(nonce);
    input.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    input.extend_from_slice(ciphertext);
    hmac_sha256(mac_key, &input)
}

fn seal(
    master: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; NONCE_BYTES], Vec<u8>, [u8; 32]), VaultError> {
    let nonce = fresh_nonce()?;
    let enc_key = derive_subkey(master, b"enc", &nonce, aad);
    let mac_key = derive_subkey(master, b"mac", &nonce, aad);
    let ciphertext = xor_keystream(&enc_key, plaintext);
    let mac = compute_mac(&mac_key, aad, &nonce, &ciphertext);
    Ok((nonce, ciphertext, mac))
}

fn open(
    master: &[u8; 32],
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    mac: &[u8],
) -> Option<Vec<u8>> {
    if nonce.len() != NONCE_BYTES || mac.len() != 32 {
        return None;
    }
    let mac_key = derive_subkey(master, b"mac", nonce, aad);
    let expected = compute_mac(&mac_key, aad, nonce, ciphertext);
    if !constant_time_eq(&expected, mac) {
        return None;
    }
    let enc_key = derive_subkey(master, b"enc", nonce, aad);
    Some(xor_keystream(&enc_key, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_open_round_trip_and_reject_tamper_or_wrong_aad() {
        let master = hmac_sha256(b"test-master-secret-32-bytes-minimum", MASTER_DOMAIN);
        let aad_alice = ByokVault::aad("person:alice", Provider::Anthropic);
        let aad_bob = ByokVault::aad("person:bob", Provider::Anthropic);
        let aad_openai = ByokVault::aad("person:alice", Provider::OpenAi);

        let secret = b"sk-ant-api03-very-secret-key-material-0123456789";
        let (nonce1, ct1, mac1) = seal(&master, &aad_alice, secret).unwrap();
        let (nonce2, ct2, _) = seal(&master, &aad_alice, secret).unwrap();
        assert_ne!(nonce1, nonce2, "nonces must be fresh");
        assert_ne!(ct1, ct2, "ciphertexts must differ across encryptions");
        assert_ne!(ct1.as_slice(), secret);

        assert_eq!(open(&master, &aad_alice, &nonce1, &ct1, &mac1).unwrap(), secret);
        // Cross-owner or cross-provider AAD substitution fails authentication.
        assert!(open(&master, &aad_bob, &nonce1, &ct1, &mac1).is_none());
        assert!(open(&master, &aad_openai, &nonce1, &ct1, &mac1).is_none());
        // Single-bit ciphertext flip fails authentication.
        let mut tampered = ct1.clone();
        tampered[0] ^= 0x01;
        assert!(open(&master, &aad_alice, &nonce1, &tampered, &mac1).is_none());
    }

    #[test]
    fn key_shape_rejects_control_chars_spaces_and_oversize() {
        assert_eq!(validate_key_shape("  sk-ant-12345  ").unwrap(), "sk-ant-12345");
        assert!(validate_key_shape("").is_err());
        assert!(validate_key_shape("   ").is_err());
        assert!(validate_key_shape("sk-ant-123\r\nx-injected: 1").is_err());
        assert!(validate_key_shape("sk-ant-123\n").is_err());
        assert!(validate_key_shape("sk-ant 123").is_err());
        assert!(validate_key_shape("sk-ant-\u{00e9}").is_err());
        assert!(validate_key_shape(&"a".repeat(1025)).is_err());
        assert!(validate_key_shape(&"a".repeat(1024)).is_ok());
    }

    #[test]
    fn mask_hint_never_reveals_full_secret() {
        assert_eq!(mask_hint("sk-ant-api03-secret-9999"), "sk-a…9999");
        assert_eq!(mask_hint("short"), "••••••••");
    }
}
