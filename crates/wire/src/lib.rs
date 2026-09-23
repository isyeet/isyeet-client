use serde::{Deserialize, Serialize};

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
    pub id_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountStateResponse {
    pub email: String,
    pub generation: String,
    pub identity_fingerprint: Option<String>,
    pub server_time: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeleteRequest {
    pub id_token: String,
    pub operation_id: String,
    pub expires_at: i64,
    pub expected_generation: String,
    pub expected_identity_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountReenrollRequest {
    pub id_token: String,
    pub operation_id: String,
    pub expires_at: i64,
    pub expected_generation: String,
    pub expected_identity_fingerprint: Option<String>,
    pub keys: KeyUpload,
}

/// Immutable destructive intent. OAuth credentials are deliberately excluded
/// from the stored intent hash so a fresh Google token can retry the operation.
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
            self.id_token,
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
            self.id_token,
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
    pub email: String,
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
    pub email: String,
    pub registration_id: u32,
    pub identity_key: String,
    pub signed_pre_key: SignedPublicPreKey,
    pub kyber_pre_key: SignedPublicPreKey,
    pub pre_key: Option<PublicPreKey>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoogleLogin {
    pub id_token: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub email: String,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRequest {
    pub email: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactPermissions {
    pub emails: Vec<String>,
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

/// Canonical account address. Gmail ignores dots; Workspace addresses preserve
/// them. Reject plus aliases and googlemail.com to avoid ambiguous identities.
/// This validates syntax only: authenticating Workspace email ownership also
/// requires google_account_email after verifying the Google token signature.
pub fn canonical_email(input: &str) -> Result<String, &'static str> {
    if !input.is_ascii() || input.len() > 254 {
        return Err("invalid email address");
    }
    let lower = input.to_ascii_lowercase();
    let (local, domain) = lower.split_once('@').ok_or("invalid email address")?;
    if local.is_empty() || local.len() > 64 || domain == "googlemail.com" {
        return Err("invalid email address");
    }
    if domain == "gmail.com" {
        // Keep established Gmail canonicalization exactly, including removal
        // of every dot before comparing account identities.
        if !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.')
        {
            return Err("use a Gmail address without plus aliases");
        }
        let local = local.replace('.', "");
        if local.is_empty() {
            return Err("invalid Gmail address");
        }
        return Ok(format!("{local}@gmail.com"));
    }
    if !valid_domain(domain)
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("invalid Workspace email address");
    }
    Ok(lower)
}

/// Apply Google's email-authority rules to claims from a verified ID token.
/// A signed hosted-domain claim establishes Workspace authority; it need not
/// equal the email's domain because organizations can have secondary domains.
pub fn google_account_email(
    email: &str,
    email_verified: bool,
    hosted_domain: Option<&str>,
) -> Result<String, &'static str> {
    if !email_verified {
        return Err("Google has not verified this email address");
    }
    let canonical = canonical_email(email)?;
    if !canonical.ends_with("@gmail.com") && !hosted_domain.is_some_and(valid_domain) {
        return Err("a verified Google Workspace hosted domain is required");
    }
    Ok(canonical)
}

fn valid_domain(domain: &str) -> bool {
    if !domain.is_ascii() || domain.len() > 253 || !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_uuid_input_is_canonical_version_four_and_bounded() {
        assert!(canonical_uuid_v4("00000000-0000-4000-8000-000000000001"));
        for value in [
            "",
            "00000000-0000-1000-8000-000000000001",
            "00000000-0000-4000-0000-000000000001",
            "00000000-0000-4000-8000-00000000000A",
            "000000000000-4000-8000-000000000001",
        ] {
            assert!(!canonical_uuid_v4(value));
        }
    }
    #[test]
    fn canonicalizes_gmail_without_alias_ambiguity() {
        assert_eq!(
            canonical_email("A.Lice@gmail.com").unwrap(),
            "alice@gmail.com"
        );
        assert_eq!(
            canonical_email(".A..Lice.@GMAIL.COM").unwrap(),
            "alice@gmail.com"
        );
        for invalid in [
            "a+b@gmail.com",
            "a@googlemail.com",
            "a@@gmail.com",
            "@gmail.com",
            ".@gmail.com",
            "a\n@gmail.com",
            "a\0@gmail.com",
            "é@gmail.com",
            " a@gmail.com",
        ] {
            assert!(canonical_email(invalid).is_err());
        }
    }
    #[test]
    fn rejects_every_non_ascii_byte_and_control_in_email() {
        for byte in 0u8..=255 {
            if byte.is_ascii_alphanumeric() || byte == b'.' {
                continue;
            }
            let candidate = format!("a{}@gmail.com", char::from(byte));
            assert!(canonical_email(&candidate).is_err(), "accepted byte {byte}");
        }
    }

    #[test]
    fn workspace_normalization_preserves_distinct_local_parts() {
        assert_eq!(
            canonical_email("A.Lice_1-Test@Secondary.EXAMPLE.com").unwrap(),
            "a.lice_1-test@secondary.example.com"
        );
        assert_ne!(
            canonical_email("A.Lice@example.com").unwrap(),
            canonical_email("Alice@example.com").unwrap()
        );
        for invalid in [
            ".alice@example.com",
            "alice.@example.com",
            "a..lice@example.com",
            "alice+alias@example.com",
            "@example.com",
            "alice@example",
            "alice@example..com",
            "alice@.example.com",
            "alice@example.com.",
            "alice@-example.com",
            "alice@example-.com",
            "alice@exa_mple.com",
            "alice@éxample.com",
            "é@example.com",
            "alice @example.com",
            "alice@example.com\n",
            "alice@example.com\0",
            "alice@@example.com",
            "alice@GOOGLEMAIL.COM",
        ] {
            assert!(canonical_email(invalid).is_err(), "accepted {invalid:?}");
        }
        for byte in 0u8..=255 {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
                continue;
            }
            let candidate = format!("a{}b@example.com", char::from(byte));
            assert!(canonical_email(&candidate).is_err(), "accepted byte {byte}");
        }
    }

    #[test]
    fn email_and_hosted_domain_length_boundaries_are_enforced() {
        let local = "a".repeat(64);
        assert!(canonical_email(&format!("{local}@example.com")).is_ok());
        assert!(canonical_email(&format!("{local}a@example.com")).is_err());
        assert!(canonical_email(&format!("a@{}.com", "a".repeat(63))).is_ok());
        assert!(canonical_email(&format!("a@{}.com", "a".repeat(64))).is_err());
        let domain = format!("{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(61));
        let maximum_email = format!("{local}@{domain}");
        assert_eq!(maximum_email.len(), 254);
        assert!(canonical_email(&maximum_email).is_ok());
        assert!(canonical_email(&format!("{maximum_email}d")).is_err());
        let maximum_domain = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(maximum_domain.len(), 253);
        assert!(google_account_email("alice@example.com", true, Some(&maximum_domain)).is_ok());
        assert!(
            google_account_email(
                "alice@example.com",
                true,
                Some(&format!("{maximum_domain}d"))
            )
            .is_err()
        );
    }

    #[test]
    fn google_authority_is_required_for_workspace_accounts() {
        assert_eq!(
            google_account_email("A.Lice@GMAIL.COM", true, None).unwrap(),
            "alice@gmail.com"
        );
        assert_eq!(
            google_account_email(
                "A.Lice@secondary.example.com",
                true,
                Some("primary.example.com")
            )
            .unwrap(),
            "a.lice@secondary.example.com"
        );
        assert!(google_account_email("alice@gmail.com", false, None).is_err());
        assert!(google_account_email("alice@example.com", false, Some("example.com")).is_err());
        assert!(google_account_email("alice@example.com", true, None).is_err());
        assert!(google_account_email("alice@googlemail.com", true, Some("example.com")).is_err());
        for hd in [
            "",
            "example",
            ".example.com",
            "example.com.",
            "example..com",
            "-example.com",
            "example-.com",
            "ex_ample.com",
            "example.com\n",
            "éxample.com",
            "a@example.com",
        ] {
            assert!(
                google_account_email("alice@example.com", true, Some(hd)).is_err(),
                "accepted hosted domain {hd:?}"
            );
        }
    }
}
