use serde::{Deserialize, Serialize};
pub mod linking;

pub const MAX_TEXT_BYTES: usize = 1024;
pub const PLAINTEXT_FRAME_BYTES: usize = 2048;
pub const ENVELOPE_BYTES: usize = 8192;
pub const MESSAGE_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const MESSAGE_FUTURE_SKEW_SECONDS: i64 = 60;
pub const NOTIFICATION_RESUME_GRACE_SECONDS: i64 = 420;
pub const ACCOUNT_OPERATION_MAX_SECONDS: i64 = 900;
pub const ACCOUNT_RECEIPT_SECONDS: i64 = 24 * 60 * 60;
pub const ACCOUNT_AUTH_MAX_AGE_SECONDS: i64 = 300;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStateRequest {
    pub action_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountStateResponse {
    pub account_id: String,
    pub username: String,
    pub generation: String,
    pub identity_fingerprint: Option<String>,
    pub server_time: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeleteRequest {
    pub action_token: String,
    pub operation_id: String,
    pub expires_at: i64,
    pub expected_generation: String,
    pub expected_identity_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountReenrollRequest {
    pub action_token: String,
    pub operation_id: String,
    pub expires_at: i64,
    pub expected_generation: String,
    pub expected_identity_fingerprint: Option<String>,
    pub keys: KeyUpload,
}

/// Immutable destructive intent; action credentials are excluded from its hash.
#[derive(Clone, Debug, Serialize)]
pub struct AccountOperation {
    pub operation_id: String,
    pub expires_at: i64,
    pub expected_generation: String,
    pub expected_identity_fingerprint: Option<String>,
    pub keys: Option<KeyUpload>,
}

impl AccountOperation {
    pub fn well_formed(&self) -> bool {
        canonical_uuid_v4(&self.operation_id)
            && canonical_uuid_v4(&self.expected_generation)
            && self
                .expected_identity_fingerprint
                .as_ref()
                .is_none_or(|pin| {
                    pin.len() == 64
                        && pin
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            && (self.keys.is_none() || self.expected_identity_fingerprint.is_some())
    }
}

pub fn canonical_uuid_v4(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 36
        && b[14] == b'4'
        && matches!(b[19], b'8' | b'9' | b'a' | b'b')
        && b.iter().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(b)
            }
        })
}

impl AccountDeleteRequest {
    pub fn into_parts(self) -> (String, AccountOperation) {
        (
            self.action_token,
            AccountOperation {
                operation_id: self.operation_id,
                expires_at: self.expires_at,
                expected_generation: self.expected_generation,
                expected_identity_fingerprint: self.expected_identity_fingerprint,
                keys: None,
            },
        )
    }
}
impl AccountReenrollRequest {
    pub fn into_parts(self) -> (String, AccountOperation) {
        (
            self.action_token,
            AccountOperation {
                operation_id: self.operation_id,
                expires_at: self.expires_at,
                expected_generation: self.expected_generation,
                expected_identity_fingerprint: self.expected_identity_fingerprint,
                keys: Some(self.keys),
            },
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountOperationResponse {
    pub operation_id: String,
    pub account_id: String,
    pub username: String,
    /// Historical durable completion, not proof that a replacement remains the
    /// current identity. Re-enrollment must log in and check its prepared key.
    pub completed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficModeRequest {
    pub cover: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficModeResponse {
    pub cover: bool,
    /// Fresh relay UTC seconds for bounding cover consent, never policy state.
    pub server_time: i64,
    /// None while cover is enabled; otherwise UTC seconds, with zero meaning
    /// notifications have never needed a quiet-mode cooldown.
    pub notifications_resume_at: Option<i64>,
}

impl TrafficModeResponse {
    pub fn notifications_enabled_at(&self, current: i64) -> bool {
        !self.cover && self.notifications_resume_at.is_some_and(|at| at <= current)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPreKey {
    pub id: u32,
    pub public_key: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPublicPreKey {
    pub id: u32,
    pub public_key: String,
    pub signature: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyUpload {
    pub registration_id: u32,
    pub identity_key: String,
    pub signed_pre_key: SignedPublicPreKey,
    pub kyber_pre_key: SignedPublicPreKey,
    pub pre_keys: Vec<PublicPreKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyMaintenanceState {
    pub generation: u32,
    pub keys: KeyUpload,
}

/// Journal this exact request and its private keys before submitting it. The
/// pre_keys array contains additions only, never an inventory replacement.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyMaintenanceRequest {
    pub operation_id: String,
    pub expected_generation: u32,
    pub keys: KeyUpload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyMaintenanceResponse {
    pub operation_id: String,
    pub generation: u32,
}

impl KeyMaintenanceRequest {
    /// Shared state-transition policy; adapters also validate serialized key
    /// sizes and commit the high-water mark, keys and retry receipt atomically.
    pub fn valid_transition(&self, current: &KeyUpload, high_water: u32, remaining: usize) -> bool {
        let unchanged = self.keys.signed_pre_key == current.signed_pre_key
            && self.keys.kyber_pre_key == current.kyber_pre_key;
        let rotation = self.keys.signed_pre_key.id > current.signed_pre_key.id
            && self.keys.kyber_pre_key.id > current.kyber_pre_key.id;
        canonical_uuid_v4(&self.operation_id)
            && self.keys.identity_key == current.identity_key
            && self.keys.registration_id == current.registration_id
            && (unchanged || rotation)
            && (rotation || !self.keys.pre_keys.is_empty())
            && remaining.saturating_add(self.keys.pre_keys.len()) <= 100
            && self.keys.pre_keys.iter().all(|key| key.id > high_water)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBundle {
    pub account_id: String,
    pub username: String,
    pub registration_id: u32,
    pub identity_key: String,
    pub signed_pre_key: SignedPublicPreKey,
    pub kyber_pre_key: SignedPublicPreKey,
    pub pre_key: Option<PublicPreKey>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub account_id: String,
    pub username: String,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRequest {
    pub account_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactPermissions {
    pub account_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    pub id: String,
    pub recipient: String,
    pub envelope: String,
    // Default permits loading old local outboxes; new server sends require a
    // positive, bounded deadline and never assign a new one on retry.
    #[serde(default)]
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueuedMessage {
    pub id: String,
    pub sender: String,
    pub envelope: String,
    pub created_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxResponse {
    pub messages: Vec<QueuedMessage>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckRequest {
    pub ids: Vec<String>,
}

/// Strict immutable account address. Never normalize malformed identifiers.
pub fn canonical_account_id(value: &str) -> Result<String, &'static str> {
    if canonical_uuid_v4(value) {
        Ok(value.to_owned())
    } else {
        Err("invalid account ID")
    }
}

/// Public directory label. Usernames are immutable and never Signal addresses.
pub fn canonical_username(value: &str) -> Result<String, &'static str> {
    let b = value.as_bytes();
    if (3..=24).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
    {
        Ok(value.to_owned())
    } else {
        Err("invalid username")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryLookup {
    pub username: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryResponse {
    pub account_id: String,
    pub username: String,
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    #[test]
    fn identifiers_are_strict_and_never_normalized() {
        assert!(canonical_account_id("00000000-0000-4000-8000-000000000001").is_ok());
        for bad in [
            "00000000-0000-1000-8000-000000000001",
            "00000000-0000-4000-8000-00000000000A",
            "alice@gmail.com",
            "",
        ] {
            assert!(canonical_account_id(bad).is_err());
        }
        for valid in ["abc", "alice_123", "abcdefghijklmnopqrstuvwx"] {
            assert_eq!(canonical_username(valid).unwrap(), valid);
        }
        for bad in [
            "ab",
            "Alice",
            "alice@gmail.com",
            "_alice",
            "1alice",
            "alice.smith",
            "alice-smith",
            "alice ",
            "alíce",
            "abcdefghijklmnopqrstuvwxy",
        ] {
            assert!(canonical_username(bad).is_err());
        }
    }
    #[test]
    fn old_email_requests_and_unknown_fields_are_rejected() {
        assert!(serde_json::from_str::<ContactRequest>(r#"{"email":"alice@gmail.com"}"#).is_err());
        assert!(
            serde_json::from_str::<DirectoryLookup>(r#"{"username":"alice","account_id":"x"}"#)
                .is_err()
        );
    }
}
