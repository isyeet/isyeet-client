//! Experimental device-authority records. These grant no v2 messaging access.
//! Signatures use official libsignal; this module only specifies bounded,
//! domain-separated canonical transcripts shared by every verifier.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEVICE_ROSTER_LIFETIME: i64 = 86_400;
pub const DEVICE_LINK_LIFETIME: i64 = 300;
pub const DEVICE_TIME_SKEW: i64 = 60;
pub const MAX_ACTIVE_DEVICES: usize = 2;
pub const MAX_DEVICE_ID: u8 = 127;
pub const MAX_DEVICE_CODE_BYTES: usize = 16_384;
pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
type Validation<T> = Result<T, &'static str>;
const INVALID: &str = "invalid_device_authority";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCertificate {
    pub account_id: String,
    pub root_epoch: String,
    pub device_id: u8,
    pub identity_key: String,
    pub registration_id: u32,
    pub label: String,
    pub request_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDeviceCertificate {
    pub certificate: DeviceCertificate,
    pub signature: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRoster {
    pub origin: String,
    pub account_id: String,
    pub root_epoch: String,
    pub root_identity_key: String,
    pub version: u64,
    pub previous_hash: String,
    pub highest_device_id: u8,
    pub issued_at: i64,
    pub expires_at: i64,
    pub devices: Vec<SignedDeviceCertificate>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDeviceRoster {
    pub roster: DeviceRoster,
    pub signature: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceLinkRequest {
    pub origin: String,
    pub account_id: String,
    pub root_epoch: String,
    pub root_identity_key: String,
    pub request_id: String,
    pub identity_key: String,
    pub registration_id: u32,
    pub label: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDeviceLinkRequest {
    pub request: DeviceLinkRequest,
    pub signature: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceChange {
    pub operation_id: String,
    pub expires_at: i64,
    pub expected_version: u64,
    pub expected_roster_hash: String,
    pub roster: SignedDeviceRoster,
    pub link_request: Option<SignedDeviceLinkRequest>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDeviceChange {
    pub change: DeviceChange,
    pub signature: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorityUpdate {
    pub action_token: String,
    pub change: SignedDeviceChange,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorityResponse {
    pub authority: Option<SignedDeviceRoster>,
    pub server_time: i64,
    pub messaging_available: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthorityReceipt {
    pub operation_id: String,
    pub roster_version: u64,
    pub roster_hash: String,
    pub messaging_available: bool,
}

pub fn decode_public_key(value: &str) -> Validation<Vec<u8>> {
    let bytes = decode_standard(value, 33)?;
    if bytes[0] != 5 {
        return Err(INVALID);
    }
    Ok(bytes)
}
pub fn decode_signature(value: &str) -> Validation<Vec<u8>> {
    decode_standard(value, 64)
}
fn decode_standard(value: &str, size: usize) -> Validation<Vec<u8>> {
    if value.len() > 128 {
        return Err(INVALID);
    }
    let bytes = STANDARD.decode(value).map_err(|_| INVALID)?;
    if bytes.len() != size || STANDARD.encode(&bytes) != value {
        return Err(INVALID);
    }
    Ok(bytes)
}
pub fn decode_nonce(value: &str) -> Validation<Vec<u8>> {
    if value.len() != 43 {
        return Err(INVALID);
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| INVALID)?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(INVALID);
    }
    Ok(bytes)
}
pub fn decode_hash(value: &str) -> Validation<Vec<u8>> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(INVALID);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|part| {
            let nibble = |b: u8| {
                if b.is_ascii_digit() {
                    b - b'0'
                } else {
                    b - b'a' + 10
                }
            };
            Ok((nibble(part[0]) << 4) | nibble(part[1]))
        })
        .collect()
}
pub fn transcript_hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn valid_device_origin(origin: &str) -> bool {
    if origin.len() > 256 || !origin.is_ascii() {
        return false;
    }
    if let Some(port) = origin
        .strip_prefix("http://127.0.0.1:")
        .or_else(|| origin.strip_prefix("http://[::1]:"))
    {
        return !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
            && port
                .parse::<u16>()
                .is_ok_and(|p| p > 0 && p.to_string() == port);
    }
    let Some(host) = origin.strip_prefix("https://") else {
        return false;
    };
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && label.as_bytes()[0] != b'-'
                && label.as_bytes()[label.len() - 1] != b'-'
        })
}
pub fn valid_device_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 32
        && label.trim() == label
        && label.bytes().all(|b| (32..=126).contains(&b))
}
fn uuid(value: &str) -> Validation<()> {
    if crate::canonical_uuid_v4(value) {
        Ok(())
    } else {
        Err(INVALID)
    }
}
fn time(value: i64) -> bool {
    value >= 0 && (value as u64) <= MAX_SAFE_INTEGER
}
fn interval(start: i64, end: i64, maximum: i64) -> bool {
    time(start) && time(end) && end > start && end - start <= maximum
}
fn current(start: i64, end: i64, now: i64) -> bool {
    time(now) && start <= now.saturating_add(DEVICE_TIME_SKEW) && end > now
}
struct Transcript(Vec<u8>);
impl Transcript {
    fn new(domain: &[u8]) -> Self {
        let mut bytes = vec![0xff; 32];
        bytes.extend_from_slice(domain);
        bytes.push(0);
        Self(bytes)
    }
    fn bytes(&mut self, value: &[u8]) {
        self.0
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.0.extend_from_slice(value);
    }
    fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    fn i64(&mut self, value: i64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
}
impl DeviceCertificate {
    pub fn validate_shape(&self) -> Validation<()> {
        uuid(&self.account_id)?;
        uuid(&self.root_epoch)?;
        decode_public_key(&self.identity_key)?;
        decode_hash(&self.request_hash)?;
        if !(1..=MAX_DEVICE_ID).contains(&self.device_id)
            || !(1..=16380).contains(&self.registration_id)
            || !valid_device_label(&self.label)
            || (self.device_id == 1 && self.request_hash != ZERO_HASH)
            || (self.device_id != 1 && self.request_hash == ZERO_HASH)
        {
            return Err(INVALID);
        }
        Ok(())
    }
    pub fn signing_bytes(&self) -> Validation<Vec<u8>> {
        self.validate_shape()?;
        let mut t = Transcript::new(b"ISYEET_DEVICE_CERTIFICATE_V1");
        t.text(&self.account_id);
        t.text(&self.root_epoch);
        t.u8(self.device_id);
        t.bytes(&decode_public_key(&self.identity_key)?);
        t.u32(self.registration_id);
        t.text(&self.label);
        t.bytes(&decode_hash(&self.request_hash)?);
        Ok(t.0)
    }
    pub fn digest(&self) -> Validation<String> {
        Ok(transcript_hash(&self.signing_bytes()?))
    }
}
impl DeviceRoster {
    pub fn validate_shape(&self) -> Validation<()> {
        uuid(&self.account_id)?;
        uuid(&self.root_epoch)?;
        decode_public_key(&self.root_identity_key)?;
        decode_hash(&self.previous_hash)?;
        if !valid_device_origin(&self.origin)
            || self.version == 0
            || self.version > MAX_SAFE_INTEGER
            || !(1..=MAX_DEVICE_ID).contains(&self.highest_device_id)
            || !interval(self.issued_at, self.expires_at, DEVICE_ROSTER_LIFETIME)
            || self.devices.is_empty()
            || self.devices.len() > MAX_ACTIVE_DEVICES
        {
            return Err(INVALID);
        }
        let mut previous = 0;
        for signed in &self.devices {
            let d = &signed.certificate;
            d.validate_shape()?;
            decode_signature(&signed.signature)?;
            if d.account_id != self.account_id
                || d.root_epoch != self.root_epoch
                || d.device_id <= previous
                || d.device_id > self.highest_device_id
            {
                return Err(INVALID);
            }
            previous = d.device_id;
        }
        if self.devices[0].certificate.device_id != 1
            || self.devices[0].certificate.identity_key != self.root_identity_key
        {
            return Err(INVALID);
        }
        if self.devices.len() == 2
            && self.devices[1].certificate.identity_key == self.root_identity_key
        {
            return Err(INVALID);
        }
        Ok(())
    }
    pub fn valid_at(&self, now: i64) -> bool {
        self.validate_shape().is_ok() && current(self.issued_at, self.expires_at, now)
    }
    pub fn signing_bytes(&self) -> Validation<Vec<u8>> {
        self.validate_shape()?;
        let mut t = Transcript::new(b"ISYEET_DEVICE_ROSTER_V1");
        t.text(&self.origin);
        t.text(&self.account_id);
        t.text(&self.root_epoch);
        t.bytes(&decode_public_key(&self.root_identity_key)?);
        t.u64(self.version);
        t.bytes(&decode_hash(&self.previous_hash)?);
        t.u8(self.highest_device_id);
        t.i64(self.issued_at);
        t.i64(self.expires_at);
        t.u8(self.devices.len() as u8);
        for d in &self.devices {
            t.bytes(&d.certificate.signing_bytes()?);
            t.bytes(&decode_signature(&d.signature)?);
        }
        Ok(t.0)
    }
    pub fn digest(&self) -> Validation<String> {
        Ok(transcript_hash(&self.signing_bytes()?))
    }
}
impl DeviceLinkRequest {
    pub fn validate_shape(&self) -> Validation<()> {
        uuid(&self.account_id)?;
        uuid(&self.root_epoch)?;
        uuid(&self.request_id)?;
        decode_public_key(&self.root_identity_key)?;
        decode_public_key(&self.identity_key)?;
        decode_nonce(&self.nonce)?;
        if !valid_device_origin(&self.origin)
            || !(1..=16380).contains(&self.registration_id)
            || !valid_device_label(&self.label)
            || self.identity_key == self.root_identity_key
            || !interval(self.issued_at, self.expires_at, DEVICE_LINK_LIFETIME)
        {
            return Err(INVALID);
        }
        Ok(())
    }
    pub fn valid_at(&self, now: i64) -> bool {
        self.validate_shape().is_ok() && current(self.issued_at, self.expires_at, now)
    }
    pub fn signing_bytes(&self) -> Validation<Vec<u8>> {
        self.validate_shape()?;
        let mut t = Transcript::new(b"ISYEET_DEVICE_LINK_V1");
        t.text(&self.origin);
        t.text(&self.account_id);
        t.text(&self.root_epoch);
        t.bytes(&decode_public_key(&self.root_identity_key)?);
        t.text(&self.request_id);
        t.bytes(&decode_public_key(&self.identity_key)?);
        t.u32(self.registration_id);
        t.text(&self.label);
        t.bytes(&decode_nonce(&self.nonce)?);
        t.i64(self.issued_at);
        t.i64(self.expires_at);
        Ok(t.0)
    }
    pub fn digest(&self) -> Validation<String> {
        Ok(transcript_hash(&self.signing_bytes()?))
    }
}
impl DeviceChange {
    pub fn validate_shape(&self) -> Validation<()> {
        uuid(&self.operation_id)?;
        decode_hash(&self.expected_roster_hash)?;
        self.roster.roster.validate_shape()?;
        decode_signature(&self.roster.signature)?;
        if self.expected_version >= MAX_SAFE_INTEGER
            || self.roster.roster.version <= self.expected_version
            || self.roster.roster.previous_hash != self.expected_roster_hash
            || (self.expected_version == 0 && self.expected_roster_hash != ZERO_HASH)
            || !interval(
                self.roster.roster.issued_at,
                self.expires_at,
                DEVICE_LINK_LIFETIME,
            )
        {
            return Err(INVALID);
        }
        if let Some(link) = &self.link_request {
            link.request.validate_shape()?;
            decode_signature(&link.signature)?;
        }
        Ok(())
    }
    pub fn valid_at(&self, now: i64) -> bool {
        self.validate_shape().is_ok()
            && self.roster.roster.valid_at(now)
            && current(self.roster.roster.issued_at, self.expires_at, now)
            && self
                .link_request
                .as_ref()
                .is_none_or(|link| link.request.valid_at(now))
    }
    pub fn signing_bytes(&self) -> Validation<Vec<u8>> {
        self.validate_shape()?;
        let mut t = Transcript::new(b"ISYEET_DEVICE_CHANGE_V1");
        t.text(&self.operation_id);
        t.i64(self.expires_at);
        t.u64(self.expected_version);
        t.bytes(&decode_hash(&self.expected_roster_hash)?);
        t.bytes(&self.roster.roster.signing_bytes()?);
        t.bytes(&decode_signature(&self.roster.signature)?);
        if let Some(link) = &self.link_request {
            t.u8(1);
            t.bytes(&link.request.signing_bytes()?);
            t.bytes(&decode_signature(&link.signature)?);
        } else {
            t.u8(0);
        }
        Ok(t.0)
    }
    pub fn digest(&self) -> Validation<String> {
        Ok(transcript_hash(&self.signing_bytes()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encodings_are_exact_and_context_is_bounded() {
        let key = STANDARD.encode([&[5][..], &[7; 32][..]].concat());
        assert_eq!(decode_public_key(&key).unwrap().len(), 33);
        assert!(decode_public_key(&STANDARD.encode([&[5][..], &[7; 33][..]].concat())).is_err());
        assert!(decode_public_key(&STANDARD.encode([7; 33])).is_err());
        assert!(decode_signature(&STANDARD.encode([7; 64])).is_ok());
        assert!(decode_signature(&STANDARD.encode([7; 65])).is_err());
        assert!(decode_nonce(&URL_SAFE_NO_PAD.encode([3; 32])).is_ok());
        assert!(decode_hash(ZERO_HASH).is_ok());
        assert!(decode_hash(&"A".repeat(64)).is_err());
        for origin in [
            "https://api.isyeet.io",
            "http://127.0.0.1:8787",
            "http://[::1]:8787",
        ] {
            assert!(valid_device_origin(origin));
        }
        for origin in [
            "https://api.isyeet.io/",
            "https://evil@api.isyeet.io",
            "https://api.isyeet.io#x",
            "https://api.isyeet.io:443",
            "http://example.com",
            "http://127.0.0.1:08787",
        ] {
            assert!(!valid_device_origin(origin));
        }
        for label in ["", " bad", "bad ", "a\nb", "\u{1f600}"] {
            assert!(!valid_device_label(label));
        }
    }
}
