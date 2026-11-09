//! Minimal shared Signal client. Every operation proposes a complete new state;
//! callers must persist it atomically before releasing ciphertext or acknowledging.
mod contacts;
#[cfg(feature = "device-linking")]
mod device_authority;
mod groups;
mod maintenance;
mod store;
mod traffic;
use anyhow::{Result, bail, ensure};
#[cfg(feature = "device-linking")]
pub use device_authority::{
    DeviceCandidate, verify_device_change, verify_device_link, verify_device_roster,
};
pub use groups::{Group, GroupMember, OutboxRef};
use isyeet_wire::*;
use libsignal_protocol::*;
use rand::{Rng, RngCore, TryRngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString, c_char},
    time::{SystemTime, UNIX_EPOCH},
};
use store::*;

pub const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;
const SECURITY_ALERT: &str = "Security alert: message rejected.";
const CONTACT_REPLACEMENT_REJECTED: &str =
    "Contact replacement rejected; existing contact remains unchanged.";

#[derive(Clone, Serialize, Deserialize)]
pub struct State {
    version: u32,
    #[serde(default)]
    traffic: traffic::TrafficState,
    pub account_id: String,
    pub username: String,
    contact_usernames: std::collections::BTreeMap<String, String>,
    identities: Identities,
    sessions: Sessions,
    prekeys: PreKeys,
    signed: SignedPreKeys,
    kyber: KyberPreKeys,
    upload: KeyUpload,
    verified: BTreeSet<String>,
    pub outbox: Vec<SendRequest>,
    pub messages: Vec<LocalMessage>,
    received: Vec<ReceivedRecord>,
    #[serde(default)]
    last_observed_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    self_channel: Option<SelfChannel>,
    #[serde(default)]
    groups: std::collections::BTreeMap<String, Group>,
    #[serde(default)]
    group_outbox: std::collections::BTreeMap<String, OutboxRef>,
    #[serde(default)]
    logical_received: Vec<groups::LogicalRecord>,
    #[serde(default)]
    deferred_groups: Vec<groups::DeferredGroup>,
    #[serde(skip)]
    resolved_message_ids: Vec<String>,
    #[serde(default)]
    group_identity_warnings: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    removed_contacts: Vec<contacts::RemovedContact>,
    #[serde(default)]
    key_maintenance: maintenance::KeyMaintenanceState,
    #[cfg(feature = "device-linking")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_authority: Option<device_authority::DeviceAuthorityState>,
    // Default builds preserve experimental allocation watermarks losslessly,
    // but cannot interpret them or expose any authority operation.
    #[cfg(not(feature = "device-linking"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_authority: Option<Value>,
}

/// Two distinct Signal endpoints for the same local identity. Their session and
/// prekey stores never overlap the stores used by remote contacts.
#[derive(Clone, Serialize, Deserialize)]
struct SelfChannel {
    outgoing: Sessions,
    incoming: Sessions,
    prekeys: PreKeys,
    signed: SignedPreKeys,
    kyber: KyberPreKeys,
}

impl SelfChannel {
    async fn initialize(account_id: &str, identities: &mut Identities) -> Result<Self> {
        let identity = identities.get_identity_key_pair().await?;
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let one_time = KeyPair::generate(&mut rng);
        let signed_pair = KeyPair::generate(&mut rng);
        let signature = identity
            .private_key()
            .calculate_signature(&signed_pair.public_key.serialize(), &mut rng)?;
        let timestamp = Timestamp::from_epoch_millis(
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
        );
        let signed_record = SignedPreKeyRecord::new(1.into(), timestamp, &signed_pair, &signature);
        let kyber_record =
            KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, 1.into(), identity.private_key())?;
        let bundle = PreKeyBundle::new(
            identities.registration,
            DeviceId::new(1)?,
            Some((1.into(), one_time.public_key)),
            1.into(),
            signed_pair.public_key,
            signature.to_vec(),
            1.into(),
            kyber_record.public_key()?,
            kyber_record.signature()?.to_vec(),
            *identity.identity_key(),
        )?;
        let mut channel = Self {
            outgoing: Default::default(),
            incoming: Default::default(),
            prekeys: Default::default(),
            signed: Default::default(),
            kyber: Default::default(),
        };
        channel
            .prekeys
            .save_pre_key(1.into(), &PreKeyRecord::new(1.into(), &one_time))
            .await?;
        channel
            .signed
            .save_signed_pre_key(1.into(), &signed_record)
            .await?;
        channel
            .kyber
            .save_kyber_pre_key(1.into(), &kyber_record)
            .await?;
        process_prekey_bundle(
            &address(account_id),
            &address(account_id),
            &mut channel.outgoing,
            identities,
            &bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await?;
        // Complete Signal's authenticated session establishment locally. A
        // sending endpoint which never receives a reply remains a pending
        // prekey session and upstream refuses to use it after 30 days. These
        // fixed setup bytes contain no user text and never become messages or
        // relay traffic; user ciphertext still waits for real relay delivery.
        const HELLO: &[u8] = b"ISYEET local self-session setup v1";
        const ACK: &[u8] = b"ISYEET local self-session setup acknowledgment v1";
        let hello = message_encrypt(
            HELLO,
            &address(account_id),
            &address(account_id),
            &mut channel.outgoing,
            identities,
            SystemTime::now(),
            &mut rng,
        )
        .await?;
        let received = message_decrypt(
            &hello,
            &address(account_id),
            &address(account_id),
            &mut channel.incoming,
            identities,
            &mut channel.prekeys,
            &channel.signed,
            &mut channel.kyber,
            &mut rng,
        )
        .await?;
        ensure!(received == HELLO, SECURITY_ALERT);
        let reply = message_encrypt(
            ACK,
            &address(account_id),
            &address(account_id),
            &mut channel.incoming,
            identities,
            SystemTime::now(),
            &mut rng,
        )
        .await?;
        let received = message_decrypt(
            &reply,
            &address(account_id),
            &address(account_id),
            &mut channel.outgoing,
            identities,
            &mut channel.prekeys,
            &channel.signed,
            &mut channel.kyber,
            &mut rng,
        )
        .await?;
        ensure!(received == ACK, SECURITY_ALERT);
        Ok(channel)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalMessage {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_alert: Option<String>,
    pub duplicate: bool,
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub expired: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_count: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_count: Option<u8>,
    #[serde(default)]
    pub deferred: bool,
    #[serde(default)]
    pub cover: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum ReceivedRecord {
    Dated { key: String, expires_at: i64 },
    Legacy(String),
}

fn current_time() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}
fn deadline(current: i64) -> Result<i64> {
    ensure!(current > 0, "Invalid clock.");
    current
        .checked_add(MESSAGE_LIFETIME_SECONDS)
        .ok_or_else(|| anyhow::anyhow!("Invalid clock."))
}
fn valid_deadline(expires_at: i64, current: i64) -> bool {
    expires_at
        .checked_sub(MESSAGE_LIFETIME_SECONDS)
        .is_some_and(|sent_at| {
            sent_at > 0 && sent_at <= current.saturating_add(MESSAGE_FUTURE_SKEW_SECONDS)
        })
}

pub fn valid_text(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= MAX_TEXT_BYTES
        && bytes.iter().all(|b| (0x20..=0x7e).contains(b))
}
fn frame(text: &[u8], expires_at: i64) -> Result<Vec<u8>> {
    ensure!(
        valid_text(text),
        "Only 1-1024 printable ASCII bytes are accepted."
    );
    let mut bytes = vec![0; PLAINTEXT_FRAME_BYTES];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut bytes);
    bytes[..4].copy_from_slice(b"ISY2");
    bytes[4..12].copy_from_slice(&expires_at.to_be_bytes());
    bytes[12..14].copy_from_slice(&(text.len() as u16).to_be_bytes());
    bytes[14..14 + text.len()].copy_from_slice(text);
    Ok(bytes)
}
struct DecodedFrame {
    text: Option<String>,
    expires_at: i64,
}
fn unframe(bytes: &[u8], current: i64) -> Result<DecodedFrame> {
    ensure!(bytes.len() == PLAINTEXT_FRAME_BYTES, SECURITY_ALERT);
    // An authenticated legacy frame has no authenticated send time. Consume its
    // ratchet and ACK it without converting or exposing undated plaintext.
    if &bytes[..4] == b"ISY1" {
        let len = usize::from(u16::from_be_bytes(bytes[4..6].try_into()?));
        ensure!(len > 0 && len <= MAX_TEXT_BYTES, SECURITY_ALERT);
        ensure!(valid_text(&bytes[6..6 + len]), SECURITY_ALERT);
        return Ok(DecodedFrame {
            text: None,
            expires_at: 0,
        });
    }
    ensure!(&bytes[..4] == b"ISY2", SECURITY_ALERT);
    let expires_at = i64::from_be_bytes(bytes[4..12].try_into()?);
    ensure!(valid_deadline(expires_at, current), SECURITY_ALERT);
    let len = usize::from(u16::from_be_bytes(bytes[12..14].try_into()?));
    ensure!(len > 0 && len <= MAX_TEXT_BYTES, SECURITY_ALERT);
    let text = &bytes[14..14 + len];
    ensure!(valid_text(text), SECURITY_ALERT);
    // Expired plaintext is never converted to a String or returned for display.
    Ok(DecodedFrame {
        text: (expires_at > current)
            .then(|| String::from_utf8(text.to_vec()))
            .transpose()?,
        expires_at,
    })
}
fn address(account_id: &str) -> ProtocolAddress {
    ProtocolAddress::new(
        account_id.to_owned(),
        DeviceId::new(1).expect("constant device ID"),
    )
}
fn fingerprint(identity: &str) -> Result<String> {
    Ok(Sha256::digest(decode(identity)?)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
fn normalized(input: &str) -> Result<String> {
    canonical_account_id(input).map_err(anyhow::Error::msg)
}

impl State {
    pub async fn initialize(account_id: &str, username: &str) -> Result<Self> {
        let account_id = normalized(account_id)?;
        let username = canonical_username(username).map_err(anyhow::Error::msg)?;
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let identity = IdentityKeyPair::generate(&mut rng);
        let registration = rng.random_range(1..16380);
        let signed_pair = KeyPair::generate(&mut rng);
        let signed_signature = identity
            .private_key()
            .calculate_signature(&signed_pair.public_key.serialize(), &mut rng)?;
        let timestamp = Timestamp::from_epoch_millis(
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
        );
        let signed_record =
            SignedPreKeyRecord::new(1.into(), timestamp, &signed_pair, &signed_signature);
        let kyber_record =
            KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, 1.into(), identity.private_key())?;
        let mut prekeys = PreKeys::default();
        let mut public_prekeys = Vec::new();
        for id in 1..=32 {
            let pair = KeyPair::generate(&mut rng);
            prekeys
                .save_pre_key(id.into(), &PreKeyRecord::new(id.into(), &pair))
                .await?;
            public_prekeys.push(PublicPreKey {
                id,
                public_key: encode(pair.public_key.serialize()),
            });
        }
        let upload = KeyUpload {
            registration_id: registration,
            identity_key: encode(identity.identity_key().serialize()),
            signed_pre_key: SignedPublicPreKey {
                id: 1,
                public_key: encode(signed_pair.public_key.serialize()),
                signature: encode(signed_signature),
            },
            kyber_pre_key: SignedPublicPreKey {
                id: 1,
                public_key: encode(kyber_record.public_key()?.serialize()),
                signature: encode(kyber_record.signature()?),
            },
            pre_keys: public_prekeys,
        };
        let mut signed = SignedPreKeys::default();
        signed.save_signed_pre_key(1.into(), &signed_record).await?;
        let mut kyber = KyberPreKeys::default();
        kyber.save_kyber_pre_key(1.into(), &kyber_record).await?;
        Ok(Self {
            version: 7,
            traffic: Default::default(),
            account_id,
            username,
            contact_usernames: Default::default(),
            identities: Identities {
                pair: encode(identity.serialize()),
                registration,
                known: Default::default(),
            },
            sessions: Default::default(),
            prekeys,
            signed,
            kyber,
            upload,
            verified: Default::default(),
            outbox: Vec::new(),
            messages: Vec::new(),
            received: Vec::new(),
            last_observed_at: current_time()?,
            self_channel: None,
            groups: Default::default(),
            group_outbox: Default::default(),
            logical_received: Default::default(),
            deferred_groups: Default::default(),
            resolved_message_ids: Default::default(),
            group_identity_warnings: Default::default(),
            removed_contacts: Default::default(),
            key_maintenance: maintenance::KeyMaintenanceState::new(current_time()?),
            device_authority: None,
        })
    }
    /// Propose deletion of expired message material, preserving all crypto state.
    /// Persist before adopting/displaying this state or performing any network action.
    pub fn expire(&mut self) -> Result<bool> {
        self.expire_at(current_time()?)
    }
    fn expire_at(&mut self, observed: i64) -> Result<bool> {
        self.expire_at_with_resolution(observed, true)
    }
    fn expire_at_with_resolution(&mut self, observed: i64, resolve: bool) -> Result<bool> {
        ensure!(observed > 0, "Invalid state or clock.");
        self.validate_identity_schema()?;
        let current = observed.max(self.last_observed_at);
        let before = (
            self.outbox.len(),
            self.messages.len(),
            self.received.len(),
            self.version,
            self.last_observed_at,
            self.group_outbox.len(),
            self.logical_received.len(),
            self.deferred_groups.len(),
            self.groups.len(),
        );
        self.outbox
            .retain(|m| m.expires_at > current && valid_deadline(m.expires_at, current));
        self.messages.retain(|m| {
            !m.expired && m.expires_at > current && valid_deadline(m.expires_at, current)
        });
        self.received.retain(|entry| matches!(entry, ReceivedRecord::Dated { expires_at, .. } if *expires_at > current));
        self.group_outbox
            .retain(|id, _| self.outbox.iter().any(|message| &message.id == id));
        self.logical_received
            .retain(|entry| entry.expires_at > current);
        self.deferred_groups
            .retain(|entry| entry.expires_at > current);
        if resolve {
            self.resolve_deferred_groups(current)?;
        }
        self.retire_groups(current);
        let removed_changed = self.prune_removed_contacts(current);
        let traffic_changed = self.prune_traffic(current);
        let keys_changed = self.prune_key_material(current)?;
        self.version = 7;
        self.last_observed_at = current;
        Ok(keys_changed
            || traffic_changed
            || removed_changed
            || before
                != (
                    self.outbox.len(),
                    self.messages.len(),
                    self.received.len(),
                    self.version,
                    self.last_observed_at,
                    self.group_outbox.len(),
                    self.logical_received.len(),
                    self.deferred_groups.len(),
                    self.groups.len(),
                ))
    }
    pub fn history(&self) -> Result<Vec<LocalMessage>> {
        let mut pruned = self.clone();
        pruned.expire_at_with_resolution(current_time()?, false)?;
        Ok(pruned.messages)
    }
    pub fn key_upload(&self) -> KeyUpload {
        self.upload.clone()
    }
    pub fn verified_contacts(&self) -> Vec<String> {
        self.verified.iter().cloned().collect()
    }
    pub fn has_contact(&self, account_id: &str) -> bool {
        self.identities.known.contains_key(account_id)
    }
    /// The username protocol is a deliberate clean break. Never relabel an old
    /// Signal address or keep an email-addressed store inside a v7 envelope.
    pub fn validate_identity_schema(&self) -> Result<()> {
        let valid_id = |id: &String| canonical_account_id(id).as_ref() == Ok(id);
        ensure!(
            self.version == 7
                && valid_id(&self.account_id)
                && canonical_username(&self.username).as_ref() == Ok(&self.username)
                && self.identities.known.keys().all(valid_id)
                && self.sessions.0.keys().all(valid_id)
                && self.verified.iter().all(valid_id)
                && self.contact_usernames.iter().all(|(id, name)| valid_id(id)
                    && self.has_contact(id)
                    && canonical_username(name).as_ref() == Ok(name))
                && self.group_identity_warnings.keys().all(valid_id)
                && self
                    .groups
                    .values()
                    .all(|g| g.members.iter().all(|m| valid_id(&m.account_id)))
                && self.outbox.iter().all(|m| valid_id(&m.recipient))
                && self
                    .messages
                    .iter()
                    .all(|m| valid_id(&m.sender) && valid_id(&m.recipient))
                && self.deferred_groups.iter().all(|m| valid_id(&m.sender)),
            "Invalid or unsupported identity state; explicit enrollment is required."
        );
        Ok(())
    }
    /// Resolve only locally pinned identity metadata. Sending must never consult
    /// the directory again and silently redirect an existing contact's name.
    pub fn contact_id(&self, input: &str) -> Result<String> {
        if let Ok(account_id) = canonical_account_id(input) {
            ensure!(
                account_id == self.account_id || self.has_contact(&account_id),
                "Add the contact first."
            );
            return Ok(account_id);
        }
        let username = canonical_username(input.strip_prefix('@').unwrap_or(input))
            .map_err(anyhow::Error::msg)?;
        let mut matches = self
            .contact_usernames
            .iter()
            .filter(|(id, name)| *name == &username && self.has_contact(id))
            .map(|(id, _)| id.clone())
            .chain((self.username == username).then(|| self.account_id.clone()));
        let account_id = matches
            .next()
            .ok_or_else(|| anyhow::anyhow!("Add the contact first."))?;
        ensure!(
            matches.next().is_none(),
            "Ambiguous contact username; use its verified account ID."
        );
        Ok(account_id)
    }
    pub fn snapshot(&self) -> Result<Value> {
        let mut pruned = self.clone();
        pruned.expire_at_with_resolution(current_time()?, false)?;
        pruned.snapshot_pruned()
    }
    fn snapshot_pruned(&self) -> Result<Value> {
        let contacts: Result<Vec<Value>> = self.identities.known.iter().map(|(account_id, key)| Ok(json!({"account_id":account_id,"username":self.contact_usernames.get(account_id),"fingerprint":fingerprint(key)?,"verified":self.verified.contains(account_id)}))).collect();
        Ok(
            json!({"account_id":self.account_id,"username":self.username,"fingerprint":fingerprint(&self.upload.identity_key)?,"contacts":contacts?,"outbox":self.outbox,"messages":self.messages,"groups":self.groups.values().collect::<Vec<_>>(),"outbox_refs":self.group_outbox.values().collect::<Vec<_>>(),"pending_group_senders":self.deferred_groups.iter().map(|entry| &entry.sender).collect::<BTreeSet<_>>(),"resolved_message_ids":self.resolved_message_ids,"next_expiry":self.next_expiry(),"traffic":self.traffic_snapshot(),"key_maintenance":self.key_maintenance_snapshot()}),
        )
    }
    pub async fn add_contact(&mut self, bundle: KeyBundle) -> Result<Value> {
        self.expire()?;
        let account_id = normalized(&bundle.account_id)?;
        let username = canonical_username(&bundle.username).map_err(anyhow::Error::msg)?;
        ensure!(
            self.contact_usernames
                .get(&account_id)
                .is_none_or(|known| known == &username),
            "Contact username changed; rejected."
        );
        ensure!(
            username != self.username
                && self
                    .contact_usernames
                    .iter()
                    .all(|(id, name)| id == &account_id || name != &username),
            "Contact username points to a different account; rejected."
        );
        ensure!(
            account_id != self.account_id,
            "Cannot add your own account."
        );
        let key = IdentityKey::decode(&decode(&bundle.identity_key)?)?;
        ensure!(
            !self.removed_pin(&account_id, &fingerprint(&bundle.identity_key)?),
            "contact_identity_removed"
        );
        let addr = address(&account_id);
        ensure!(
            self.identities
                .is_trusted_identity(&addr, &key, Direction::Sending)
                .await?,
            "Contact identity changed; rejected."
        );
        // Preserve a live ratchet for an already-known identity. Re-claim must not reset it.
        if !self.sessions.0.contains_key(&account_id) {
            let prekey = bundle
                .pre_key
                .as_ref()
                .map(|k| {
                    Ok::<_, anyhow::Error>((
                        k.id.into(),
                        PublicKey::deserialize(&decode(&k.public_key)?)?,
                    ))
                })
                .transpose()?;
            let prekey_bundle = PreKeyBundle::new(
                bundle.registration_id,
                DeviceId::new(1)?,
                prekey,
                bundle.signed_pre_key.id.into(),
                PublicKey::deserialize(&decode(&bundle.signed_pre_key.public_key)?)?,
                decode(&bundle.signed_pre_key.signature)?,
                bundle.kyber_pre_key.id.into(),
                kem::PublicKey::deserialize(&decode(&bundle.kyber_pre_key.public_key)?)?,
                decode(&bundle.kyber_pre_key.signature)?,
                key,
            )?;
            process_prekey_bundle(
                &addr,
                &address(&self.account_id),
                &mut self.sessions,
                &mut self.identities,
                &prekey_bundle,
                SystemTime::now(),
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await?;
        }
        self.contact_usernames
            .insert(account_id.clone(), username.clone());
        Ok(
            json!({"account_id":account_id,"username":username,"fingerprint":fingerprint(&bundle.identity_key)?,"verified":self.verified.contains(&account_id)}),
        )
    }
    pub fn verify_contact(&mut self, account_id: &str, expected: &str) -> Result<Value> {
        self.expire()?;
        let account_id = normalized(account_id)?;
        let key = self
            .identities
            .known
            .get(&account_id)
            .ok_or_else(|| anyhow::anyhow!("Add the contact first."))?;
        let actual = fingerprint(key)?;
        ensure!(
            !self.removed_pin(&account_id, &actual),
            "contact_identity_removed"
        );
        ensure!(
            expected.len() == 64
                && expected.bytes().all(|b| b.is_ascii_hexdigit())
                && actual == expected.to_ascii_lowercase(),
            "Fingerprint mismatch; contact remains blocked."
        );
        self.verified.insert(account_id.clone());
        self.verified_readded_contact(&account_id, &actual);
        self.resolve_deferred_groups(self.last_observed_at)?;
        Ok(
            json!({"account_id":account_id,"username":self.contact_usernames.get(&account_id),"fingerprint":actual,"verified":true}),
        )
    }
    /// Explicitly replace one peer after independently verifying its new key.
    /// Validate on a clone: even a late Signal signature failure must leave the
    /// caller's original pin, session, verification and pending messages intact.
    pub async fn replace_contact(
        &mut self,
        account_id: &str,
        bundle: KeyBundle,
        previous_fingerprint: &str,
        expected_fingerprint: &str,
    ) -> Result<Value> {
        let replacement = async {
            let target = normalized(account_id)?;
            ensure!(
                target == account_id && bundle.account_id == target && target != self.account_id
            );
            let old_key = self
                .identities
                .known
                .get(&target)
                .ok_or_else(|| anyhow::anyhow!(CONTACT_REPLACEMENT_REJECTED))?;
            let previous = fingerprint(old_key)?;
            let next = fingerprint(&bundle.identity_key)?;
            ensure!(
                previous_fingerprint.len() == 64
                    && previous_fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
                    && previous_fingerprint.to_ascii_lowercase() == previous
            );
            ensure!(
                expected_fingerprint.len() == 64
                    && expected_fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
                    && expected_fingerprint.to_ascii_lowercase() == next
                    && decode(old_key)? != decode(&bundle.identity_key)?
            );
            let mut proposed = self.clone();
            proposed.remove_contact(&target, &previous)?;
            // With this peer's session removed, add_contact must construct a
            // fresh Signal session and verify both signed prekey signatures.
            // Own key material and replay/dedupe records are never reset.
            proposed.add_contact(bundle).await?;
            let contact = proposed.verify_contact(&target, expected_fingerprint)?;
            Ok::<_, anyhow::Error>((proposed, contact))
        }
        .await
        .map_err(|_| anyhow::anyhow!(CONTACT_REPLACEMENT_REJECTED))?;
        *self = replacement.0;
        Ok(replacement.1)
    }
    pub async fn encrypt(&mut self, recipient: &str, text: &str) -> Result<SendRequest> {
        self.encrypt_at(recipient, text, current_time()?).await
    }
    async fn encrypt_at(
        &mut self,
        recipient: &str,
        text: &str,
        observed: i64,
    ) -> Result<SendRequest> {
        self.expire_at(observed)?;
        let expires_at = deadline(self.last_observed_at)?;
        let recipient = normalized(recipient)?;
        let is_self = recipient == self.account_id;
        ensure!(
            is_self || self.verified.contains(&recipient),
            "contact_verification_required"
        );
        ensure!(
            self.outbox.len() < 16,
            "Outbox full; retry pending messages first."
        );
        let plaintext = frame(text.as_bytes(), expires_at)?;
        let message = self
            .encrypt_frame(&recipient, &plaintext, expires_at)
            .await?;
        if !is_self {
            self.record(LocalMessage {
                id: message.id.clone(),
                sender: self.account_id.clone(),
                recipient,
                text: Some(text.to_owned()),
                security_alert: None,
                duplicate: false,
                expires_at,
                expired: false,
                group_id: None,
                logical_id: None,
                sent_at: Some(expires_at - MESSAGE_LIFETIME_SECONDS),
                received_at: None,
                sender_fingerprint: Some(fingerprint(&self.upload.identity_key)?),
                status: Some("queued".into()),
                accepted_count: Some(0),
                recipient_count: Some(1),
                deferred: false,
                cover: false,
            });
        }
        Ok(message)
    }
    async fn encrypt_frame(
        &mut self,
        recipient: &str,
        plaintext: &[u8],
        expires_at: i64,
    ) -> Result<SendRequest> {
        let mut framed = plaintext.to_vec();
        self.write_traffic_trailer(recipient, &mut framed, expires_at);
        let plaintext = framed.as_slice();
        let is_self = recipient == self.account_id;
        let (ciphertext, self_channel) = if is_self {
            let mut identities = self.self_identities().await?;
            let mut channel = match &self.self_channel {
                Some(channel) => channel.clone(),
                None => SelfChannel::initialize(&self.account_id, &mut identities).await?,
            };
            let ciphertext = message_encrypt(
                plaintext,
                &address(&self.account_id),
                &address(&self.account_id),
                &mut channel.outgoing,
                &mut identities,
                SystemTime::now(),
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await?;
            (ciphertext, Some(channel))
        } else {
            (
                message_encrypt(
                    plaintext,
                    &address(recipient),
                    &address(&self.account_id),
                    &mut self.sessions,
                    &mut self.identities,
                    SystemTime::now(),
                    &mut rand::rngs::OsRng.unwrap_err(),
                )
                .await?,
                None,
            )
        };
        let bytes = ciphertext.serialize();
        ensure!(
            bytes.len() <= ENVELOPE_BYTES - 6,
            "Ciphertext exceeds fixed frame."
        );
        let mut envelope = vec![0; ENVELOPE_BYTES];
        rand::rngs::OsRng.unwrap_err().fill_bytes(&mut envelope);
        envelope[0] = 1;
        envelope[1] = ciphertext.message_type() as u8;
        envelope[2..6].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
        envelope[6..6 + bytes.len()].copy_from_slice(bytes);
        let message = SendRequest {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: recipient.to_owned(),
            envelope: encode(envelope),
            expires_at,
        };
        self.outbox.push(message.clone());
        if let Some(channel) = self_channel {
            self.self_channel = Some(channel);
        }
        Ok(message)
    }
    pub fn sent(&mut self, id: &str) -> Result<()> {
        self.expire()?;
        if self.outbox.iter().any(|message| message.id == id) {
            let local_id = self
                .group_outbox
                .remove(id)
                .map(|leg| leg.message_id)
                .unwrap_or_else(|| id.to_owned());
            if let Some(message) = self
                .messages
                .iter_mut()
                .find(|message| message.id == local_id)
                && let (Some(accepted), Some(total)) =
                    (message.accepted_count.as_mut(), message.recipient_count)
            {
                *accepted = accepted.saturating_add(1).min(total);
                message.status = Some(
                    if *accepted == total {
                        "relay_accepted"
                    } else {
                        "partially_accepted"
                    }
                    .into(),
                );
            }
        }
        self.outbox.retain(|m| m.id != id);
        Ok(())
    }
    fn record(&mut self, message: LocalMessage) {
        self.messages.push(message);
        if self.messages.len() > 200 {
            self.messages.remove(0);
        }
    }
    async fn self_identities(&self) -> Result<Identities> {
        let identity = self.identities.get_identity_key_pair().await?;
        Ok(Identities {
            pair: self.identities.pair.clone(),
            registration: self.identities.registration,
            known: [(
                self.account_id.clone(),
                encode(identity.identity_key().serialize()),
            )]
            .into(),
        })
    }
    async fn decrypt_inner(&mut self, sender: &str, envelope: &str) -> Result<Vec<u8>> {
        ensure!(
            envelope.len() == ENVELOPE_BYTES.div_ceil(3) * 4,
            SECURITY_ALERT
        );
        let bytes = decode(envelope)?;
        ensure!(
            bytes.len() == ENVELOPE_BYTES && bytes[0] == 1,
            SECURITY_ALERT
        );
        let len = u32::from_be_bytes(bytes[2..6].try_into()?) as usize;
        ensure!(len > 0 && len <= ENVELOPE_BYTES - 6, SECURITY_ALERT);
        let serialized = &bytes[6..6 + len];
        let ciphertext = match bytes[1] {
            2 => CiphertextMessage::SignalMessage(SignalMessage::try_from(serialized)?),
            3 => CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(serialized)?),
            _ => bail!(SECURITY_ALERT),
        };
        if sender == self.account_id {
            let mut identities = self.self_identities().await?;
            let channel = self
                .self_channel
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!(SECURITY_ALERT))?;
            return Ok(message_decrypt(
                &ciphertext,
                &address(sender),
                &address(&self.account_id),
                &mut channel.incoming,
                &mut identities,
                &mut channel.prekeys,
                &channel.signed,
                &mut channel.kyber,
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await?);
        }
        Ok(message_decrypt(
            &ciphertext,
            &address(sender),
            &address(&self.account_id),
            &mut self.sessions,
            &mut self.identities,
            &mut self.prekeys,
            &self.signed,
            &mut self.kyber,
            &mut rand::rngs::OsRng.unwrap_err(),
        )
        .await?)
    }
    pub async fn decrypt(&mut self, message: QueuedMessage) -> Result<LocalMessage> {
        self.decrypt_at(message, current_time()?).await
    }
    async fn decrypt_at(&mut self, message: QueuedMessage, observed: i64) -> Result<LocalMessage> {
        self.expire_at(observed)?;
        let current = self.last_observed_at;
        let sender = normalized(&message.sender)?;
        ensure!(
            sender == message.sender && uuid::Uuid::parse_str(&message.id).is_ok(),
            SECURITY_ALERT
        );
        let dedupe = format!("{sender}:{}", message.id);
        if self
            .received
            .iter()
            .any(|entry| matches!(entry, ReceivedRecord::Dated { key, .. } if key == &dedupe))
        {
            return Ok(LocalMessage {
                id: message.id,
                sender,
                recipient: self.account_id.clone(),
                text: None,
                security_alert: None,
                duplicate: true,
                expires_at: 0,
                expired: false,
                group_id: None,
                logical_id: None,
                sent_at: None,
                received_at: None,
                sender_fingerprint: None,
                status: None,
                accepted_count: None,
                recipient_count: None,
                deferred: false,
                cover: false,
            });
        }
        let removed_delivery = self.removed_delivery(&sender, &message.envelope);
        ensure!(
            removed_delivery || sender == self.account_id || self.verified.contains(&sender),
            "contact_verification_required"
        );
        // Authentication failure may have called stores: roll it back. Successful
        // authentication, including an expired/invalid inner frame, consumes the
        // ratchet durably so delayed traffic cannot poison the next live message.
        let original = self.clone();
        let decrypted = if removed_delivery {
            Err(anyhow::anyhow!(SECURITY_ALERT))
        } else {
            self.decrypt_inner(&sender, &message.envelope).await
        };
        let decoded = match decrypted {
            Ok(bytes) if bytes.starts_with(b"ISC1") => self
                .decode_cover(&bytes, &sender, &message.id, current)
                .ok(),
            Ok(bytes) if bytes.starts_with(b"ISG1") => {
                let decoded = self
                    .decode_group(&bytes, &sender, &message.id, current)
                    .ok();
                if let Some(frame) = &decoded {
                    self.learn_traffic(&sender, &bytes, frame.expires_at, current);
                }
                decoded
            }
            Ok(bytes) => unframe(&bytes, current).ok().map(|frame| {
                let authenticated = frame.expires_at > 0;
                if authenticated {
                    self.learn_traffic(&sender, &bytes, frame.expires_at, current);
                }
                LocalMessage {
                    id: message.id.clone(),
                    sender: sender.clone(),
                    recipient: self.account_id.clone(),
                    text: frame.text,
                    security_alert: None,
                    duplicate: false,
                    expires_at: frame.expires_at,
                    expired: frame.expires_at <= current,
                    group_id: None,
                    logical_id: None,
                    sent_at: authenticated.then_some(frame.expires_at - MESSAGE_LIFETIME_SECONDS),
                    received_at: authenticated.then_some(current),
                    sender_fingerprint: if authenticated {
                        if sender == self.account_id {
                            fingerprint(&self.upload.identity_key).ok()
                        } else {
                            self.identities
                                .known
                                .get(&sender)
                                .and_then(|key| fingerprint(key).ok())
                        }
                    } else {
                        None
                    },
                    status: authenticated.then(|| "received".into()),
                    accepted_count: None,
                    recipient_count: None,
                    deferred: false,
                    cover: false,
                }
            }),
            Err(error) => {
                *self = original;
                // A peer may have explicitly re-enrolled. Keep its first new
                // PreKey message queued until the user verifies replacement;
                // never turn an identity mismatch into a permanent ACK tombstone.
                if sender != self.account_id
                    && matches!(
                        error.downcast_ref::<SignalProtocolError>(),
                        Some(SignalProtocolError::UntrustedIdentity(_))
                    )
                {
                    bail!("contact_identity_changed");
                }
                None
            }
        };
        let received = decoded.unwrap_or(LocalMessage {
            id: message.id,
            sender,
            recipient: self.account_id.clone(),
            security_alert: Some(SECURITY_ALERT.to_owned()),
            text: None,
            duplicate: false,
            expires_at: deadline(current)?,
            expired: false,
            group_id: None,
            logical_id: None,
            sent_at: None,
            received_at: None,
            sender_fingerprint: None,
            status: None,
            accepted_count: None,
            recipient_count: None,
            deferred: false,
            cover: false,
        });
        // A content-free tombstone is needed even when the payload expired before
        // arrival, so a failed ACK can be retried without displaying an alert.
        self.received.push(ReceivedRecord::Dated {
            key: dedupe,
            expires_at: deadline(current)?,
        });
        if self.received.len() > 4096 {
            self.received.remove(0);
        }
        if !received.expired && !received.duplicate && !received.deferred && !received.cover {
            self.record(received.clone());
        }
        Ok(received)
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Invalid request."))
}
async fn dispatch(request: Value) -> Result<Value> {
    let op = field(&request, "op")?;
    #[cfg(feature = "device-linking")]
    if op.starts_with("device_candidate_") {
        ensure!(request.get("state").is_none(), "Invalid request.");
        let now = current_time()?;
        let mut candidate = if op == "device_candidate_create" {
            DeviceCandidate::create(
                serde_json::from_value(request["roster"].clone())?,
                field(&request, "label")?,
                field(&request, "root_fingerprint")?,
                now,
            )?
        } else {
            serde_json::from_value::<DeviceCandidate>(request["candidate"].clone())?
        };
        let data = match op {
            "device_candidate_create" => {
                json!({"code":candidate.code()?,"status":candidate.status()?})
            }
            "device_candidate_accept" => candidate.accept(field(&request, "code")?, now)?,
            "device_candidate_status" => candidate.status()?,
            _ => bail!("Unknown operation."),
        };
        return Ok(json!({"ok":true,"candidate":candidate,"data":data}));
    }
    let mut state = if op == "init" {
        State::initialize(field(&request, "account_id")?, field(&request, "username")?).await?
    } else {
        let state: State = serde_json::from_value(
            request
                .get("state")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Missing state."))?,
        )?;
        state.validate_identity_schema()?;
        state
    };
    if op == "block_groups_for_contact" {
        state.block_groups_for_contact_if_pin(
            field(&request, "account_id")?,
            request
                .get("fingerprint")
                .map(|_| field(&request, "fingerprint"))
                .transpose()?,
        )?;
        // A caller may migrate several warning sidecars before maintenance.
        // Prune expired bodies now, but do not promote any quarantined group
        // until every warning has been durably applied.
        state.expire_at_with_resolution(current_time()?, false)?;
    } else if op == "remove_contact" {
        // Removal must revoke the pin before any deferred group can resolve.
        state.expire_at_with_resolution(current_time()?, false)?;
    } else {
        state.expire()?;
    }
    let data = match op {
        #[cfg(feature = "device-linking")]
        "device_authority_snapshot" => state.device_authority_snapshot()?,
        #[cfg(feature = "device-linking")]
        "device_authority_observe" => state.device_authority_observe(
            field(&request, "origin")?,
            serde_json::from_value(request["authority"].clone())?,
            request["server_time"]
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("Invalid request."))?,
        )?,
        #[cfg(feature = "device-linking")]
        "device_authority_inspect" => state.device_authority_inspect(
            field(&request, "code")?,
            request["server_time"]
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("Invalid request."))?,
        )?,
        #[cfg(feature = "device-linking")]
        "device_authority_prepare" => {
            state
                .device_authority_prepare(
                    field(&request, "origin")?,
                    request["server_time"]
                        .as_i64()
                        .ok_or_else(|| anyhow::anyhow!("Invalid request."))?,
                )
                .await?
        }
        #[cfg(feature = "device-linking")]
        "device_authority_approve" => {
            state
                .device_authority_approve(
                    field(&request, "code")?,
                    field(&request, "expected_request_hash")?,
                    request["server_time"]
                        .as_i64()
                        .ok_or_else(|| anyhow::anyhow!("Invalid request."))?,
                )
                .await?
        }
        #[cfg(feature = "device-linking")]
        "device_authority_revoke" => {
            state
                .device_authority_revoke(
                    request["device_id"]
                        .as_u64()
                        .and_then(|id| u8::try_from(id).ok())
                        .ok_or_else(|| anyhow::anyhow!("Invalid request."))?,
                    request["server_time"]
                        .as_i64()
                        .ok_or_else(|| anyhow::anyhow!("Invalid request."))?,
                )
                .await?
        }
        #[cfg(feature = "device-linking")]
        "device_authority_commit" => {
            state.device_authority_commit(serde_json::from_value(request["receipt"].clone())?)?
        }
        "init" | "key_upload" => serde_json::to_value(state.key_upload())?,
        "validate_registered_keys" => {
            state.validate_registered_keys(&serde_json::from_value(request["keys"].clone())?)?;
            Value::Null
        }
        "confirm_initial_upload" => {
            state.confirm_initial_upload()?;
            state.snapshot_pruned()?
        }
        "prepare_key_maintenance" => serde_json::to_value(
            state
                .prepare_key_maintenance(serde_json::from_value(request["inventory"].clone())?)
                .await?,
        )?,
        "confirm_key_maintenance" => {
            state.confirm_key_maintenance(serde_json::from_value(request["receipt"].clone())?)?;
            state.snapshot_pruned()?
        }
        "add_contact" => {
            state
                .add_contact(serde_json::from_value(request["bundle"].clone())?)
                .await?
        }
        "verify_contact" => state.verify_contact(
            field(&request, "account_id")?,
            field(&request, "fingerprint")?,
        )?,
        "remove_contact" => state.remove_contact(
            field(&request, "account_id")?,
            field(&request, "previous_fingerprint")?,
        )?,
        "replace_contact" => {
            state
                .replace_contact(
                    field(&request, "account_id")?,
                    serde_json::from_value(request["bundle"].clone())?,
                    field(&request, "previous_fingerprint")?,
                    field(&request, "fingerprint")?,
                )
                .await?
        }
        "encrypt" => serde_json::to_value(
            state
                .encrypt(field(&request, "recipient")?, field(&request, "text")?)
                .await?,
        )?,
        "set_traffic_mode" => {
            state.set_traffic_mode(
                request
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow::anyhow!("Invalid request."))?,
            )?;
            state.snapshot_pruned()?
        }
        "create_cover" => {
            serde_json::to_value(state.create_cover(field(&request, "recipient")?).await?)?
        }
        "confirm_traffic_quiet" => {
            state.confirm_traffic_quiet(
                request
                    .get("server_time")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| anyhow::anyhow!("cover_clock_unavailable"))?,
                request
                    .get("elapsed_seconds")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| anyhow::anyhow!("cover_clock_unavailable"))?,
            )?;
            state.snapshot_pruned()?
        }
        "create_group" => serde_json::to_value(state.create_group(
            field(&request, "title")?,
            &serde_json::from_value::<Vec<String>>(request["members"].clone())?,
        )?)?,
        "encrypt_group" => serde_json::to_value(
            state
                .encrypt_group(field(&request, "group_id")?, field(&request, "text")?)
                .await?,
        )?,
        "block_groups_for_contact" => Value::Null,
        "decrypt" => serde_json::to_value(
            state
                .decrypt(serde_json::from_value(request["message"].clone())?)
                .await?,
        )?,
        "sent" => {
            state.sent(field(&request, "id")?)?;
            Value::Null
        }
        "snapshot" | "expire" => state.snapshot_pruned()?,
        "history" => serde_json::to_value(&state.messages)?,
        _ => bail!("Unknown operation."),
    };
    Ok(
        json!({"ok":true,"state":state,"data":data,"resolved_message_ids":state.resolved_message_ids}),
    )
}
/// Pure JSON transition. Error strings never include message text or crypto material.
pub fn call(input: &str) -> String {
    let result = (|| {
        ensure!(input.len() <= MAX_STATE_BYTES, "Request too large.");
        let request =
            serde_json::from_str(input).map_err(|_| anyhow::anyhow!("Invalid JSON request."))?;
        futures::executor::block_on(dispatch(request))
    })();
    match result {
        Ok(value) => value.to_string(),
        Err(error) => {
            let text = error.to_string();
            let safe = match text.as_str() {
                "key_maintenance_rejected"
                | "device_authority_rejected"
                | "device_authority_restore_required"
                | "device_authority_pending"
                | "device_authority_pending_expired"
                | "device_authority_observe_required"
                | "contact_verification_required"
                | "contact_identity_changed"
                | "contact_identity_removed"
                | contacts::REMOVAL_REJECTED
                | "group_verification_required"
                | "group_blocked"
                | "cover_unavailable"
                | "cover_clock_unavailable"
                | "Invalid group title or members."
                | "Group capacity reached."
                | "Unknown group."
                | "Only 1-1024 printable ASCII bytes are accepted."
                | "Fingerprint mismatch; contact remains blocked."
                | "Contact identity changed; rejected."
                | CONTACT_REPLACEMENT_REJECTED
                | "Outbox full; retry pending messages first."
                | "Add the contact first." => text.as_str(),
                _ => "Operation rejected; invalid input or cryptographic state.",
            };
            json!({"ok":false,"error":safe}).to_string()
        }
    }
}
/// # Safety
/// Input must point to a valid NUL-terminated C string for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isyeet_call(input: *const c_char) -> *mut c_char {
    let response = std::panic::catch_unwind(|| {
        if input.is_null() {
            return json!({"ok":false,"error":"Invalid request."}).to_string();
        }
        // SAFETY: provided by the caller's C ABI contract.
        let raw = unsafe { CStr::from_ptr(input) };
        match raw.to_str() {
            Ok(text) => call(text),
            Err(_) => json!({"ok":false,"error":"Invalid request."}).to_string(),
        }
    })
    .unwrap_or_else(|_| json!({"ok":false,"error":"Operation rejected."}).to_string());
    CString::new(response).expect("JSON escapes NUL").into_raw()
}
/// # Safety
/// Pointer must be null or a live allocation returned by isyeet_call, freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isyeet_free_string(value: *mut c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}
/// # Safety
/// Same contract as isyeet_free_string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isyeet_free(value: *mut c_char) {
    unsafe { isyeet_free_string(value) }
}

#[cfg(test)]
mod tests;
