//! Experimental root-signed device authorization. No operation in this module
//! creates a messaging session, exposes the root private key, or enables v3 sends.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use isyeet_wire::linking::*;

const REJECTED: &str = "device_authority_rejected";
const RESTORE: &str = "device_authority_restore_required";
const PENDING: &str = "device_authority_pending";
const LINK_PREFIX: &str = "ISYEET-LINK-1:";
const APPROVAL_PREFIX: &str = "ISYEET-APPROVAL-1:";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuedCandidate {
    request_id: String,
    request_hash: String,
    identity_key: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    roster: SignedDeviceRoster,
    request_expires_at: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceAuthorityState {
    version: u32,
    origin: String,
    epoch: String,
    current: Option<SignedDeviceRoster>,
    pending: Option<SignedDeviceChange>,
    allocated_version: u64,
    allocated_device_id: u8,
    issued_candidates: Vec<IssuedCandidate>,
    observed_at: i64,
    observed_hash: String,
    last_clock: i64,
    approval: Option<Approval>,
}

fn checked<T>(result: std::result::Result<T, &'static str>) -> Result<T> {
    result.map_err(anyhow::Error::msg)
}
fn verify(key: &str, bytes: &[u8], signature: &str) -> Result<()> {
    let public = canonical_key(key)?;
    ensure!(
        public.verify_signature(bytes, &checked(decode_signature(signature))?),
        REJECTED
    );
    Ok(())
}
fn canonical_key(key: &str) -> Result<PublicKey> {
    let public = PublicKey::deserialize(&checked(decode_public_key(key))?)?;
    ensure!(public.is_canonical(), REJECTED);
    Ok(public)
}
fn sign(pair: &IdentityKeyPair, bytes: &[u8]) -> Result<String> {
    Ok(encode(pair.private_key().calculate_signature(
        bytes,
        &mut rand::rngs::OsRng.unwrap_err(),
    )?))
}
pub fn verify_device_roster(signed: &SignedDeviceRoster) -> Result<()> {
    let roster = &signed.roster;
    checked(roster.validate_shape())?;
    for device in &roster.devices {
        canonical_key(&device.certificate.identity_key)?;
        verify(
            &roster.root_identity_key,
            &checked(device.certificate.signing_bytes())?,
            &device.signature,
        )?;
    }
    verify(
        &roster.root_identity_key,
        &checked(roster.signing_bytes())?,
        &signed.signature,
    )
}
pub fn verify_device_link(signed: &SignedDeviceLinkRequest) -> Result<()> {
    canonical_key(&signed.request.root_identity_key)?;
    verify(
        &signed.request.identity_key,
        &checked(signed.request.signing_bytes())?,
        &signed.signature,
    )
}
pub fn verify_device_change(signed: &SignedDeviceChange) -> Result<()> {
    checked(signed.change.validate_shape())?;
    verify_device_roster(&signed.change.roster)?;
    if let Some(link) = &signed.change.link_request {
        verify_device_link(link)?;
    }
    verify(
        &signed.change.roster.roster.root_identity_key,
        &checked(signed.change.signing_bytes())?,
        &signed.signature,
    )
}
fn encode_code<T: Serialize>(prefix: &str, value: &T) -> Result<String> {
    let code = format!(
        "{prefix}{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value)?)
    );
    ensure!(code.len() <= MAX_DEVICE_CODE_BYTES, REJECTED);
    Ok(code)
}
fn decode_code<T: serde::de::DeserializeOwned>(prefix: &str, code: &str) -> Result<T> {
    ensure!(
        code.len() <= MAX_DEVICE_CODE_BYTES && code.is_ascii(),
        REJECTED
    );
    let encoded = code
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow::anyhow!(REJECTED))?;
    let decoded = URL_SAFE_NO_PAD.decode(encoded)?;
    ensure!(URL_SAFE_NO_PAD.encode(&decoded) == encoded, REJECTED);
    Ok(serde_json::from_slice(&decoded)?)
}
fn roster_hash(roster: Option<&SignedDeviceRoster>) -> Result<String> {
    roster
        .map(|value| checked(value.roster.digest()))
        .unwrap_or_else(|| Ok(ZERO_HASH.into()))
}
fn clock(server: i64, local: i64, previous: i64) -> Result<i64> {
    ensure!(
        server > 0 && local > 0 && server.abs_diff(local) <= DEVICE_TIME_SKEW as u64,
        REJECTED
    );
    let observed = local.max(server).max(previous);
    ensure!(
        observed.abs_diff(local) <= DEVICE_TIME_SKEW as u64,
        REJECTED
    );
    Ok(observed)
}

impl DeviceAuthorityState {
    fn validate(&self, owner: &State) -> Result<()> {
        ensure!(
            self.version == 1
                && valid_device_origin(&self.origin)
                && canonical_uuid_v4(&self.epoch)
                && self.allocated_version <= MAX_SAFE_INTEGER
                && (1..=MAX_DEVICE_ID).contains(&self.allocated_device_id)
                && self.issued_candidates.len() <= 126,
            REJECTED
        );
        for issued in &self.issued_candidates {
            ensure!(canonical_uuid_v4(&issued.request_id), REJECTED);
            checked(decode_hash(&issued.request_hash))?;
            checked(decode_public_key(&issued.identity_key))?;
        }
        checked(decode_hash(&self.observed_hash))?;
        if let Some(current) = &self.current {
            verify_device_roster(current)?;
            self.matches_owner(owner, &current.roster)?;
            ensure!(
                current.roster.version <= self.allocated_version
                    && current.roster.highest_device_id <= self.allocated_device_id,
                RESTORE
            );
        }
        if let Some(pending) = &self.pending {
            verify_device_change(pending)?;
            self.matches_owner(owner, &pending.change.roster.roster)?;
            ensure!(
                pending.change.expected_version
                    == self.current.as_ref().map_or(0, |r| r.roster.version)
                    && pending.change.expected_roster_hash == roster_hash(self.current.as_ref())?
                    && pending.change.roster.roster.version == self.allocated_version
                    && pending.change.roster.roster.highest_device_id <= self.allocated_device_id,
                REJECTED
            );
        }
        Ok(())
    }
    fn matches_owner(&self, owner: &State, roster: &DeviceRoster) -> Result<()> {
        ensure!(
            roster.origin == self.origin
                && roster.account_id == owner.account_id
                && roster.root_epoch == self.epoch
                && roster.root_identity_key == owner.upload.identity_key
                && roster.devices[0].certificate.registration_id == owner.upload.registration_id,
            RESTORE
        );
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| anyhow::anyhow!(REJECTED))?;
        self.approval = pending.change.link_request.as_ref().map(|link| Approval {
            roster: pending.change.roster.clone(),
            request_expires_at: link.request.expires_at,
        });
        self.current = Some(pending.change.roster);
        self.observed_at = 0;
        Ok(())
    }
    fn data(&self, now: i64) -> Result<Value> {
        let approval_code = if self.pending.is_none()
            && self.observed_at > 0
            && self.observed_at.abs_diff(now) <= DEVICE_TIME_SKEW as u64
            && self.observed_hash == roster_hash(self.current.as_ref())?
        {
            self.approval
                .as_ref()
                .filter(|a| {
                    a.request_expires_at > now
                        && a.roster.roster.valid_at(now)
                        && self.current.as_ref().is_some_and(|current| {
                            current.roster.valid_at(now)
                                && current.roster.devices.iter().any(|d| {
                                    a.roster.roster.devices.last() == Some(d)
                                        && d.certificate.device_id != 1
                                })
                        })
                })
                .map(|a| encode_code(APPROVAL_PREFIX, &a.roster))
                .transpose()?
        } else {
            None
        };
        Ok(
            json!({"authority":self.current,"pending":self.pending,"approval_code":approval_code,
            "allocated_version":self.allocated_version,"allocated_device_id":self.allocated_device_id,"messaging_available":false}),
        )
    }
    fn can_propose(&self, now: i64) -> Result<()> {
        ensure!(self.pending.is_none(), PENDING);
        ensure!(
            self.observed_at > 0
                && now >= self.observed_at
                && now - self.observed_at <= DEVICE_TIME_SKEW
                && self.observed_hash == roster_hash(self.current.as_ref())?,
            "device_authority_observe_required"
        );
        Ok(())
    }
}

impl State {
    pub fn device_authority_snapshot(&self) -> Result<Value> {
        if let Some(authority) = &self.device_authority {
            authority.validate(self)?;
            authority.data(current_time()?)
        } else {
            Ok(
                json!({"authority":null,"pending":null,"approval_code":null,"allocated_version":0,"allocated_device_id":1,"messaging_available":false}),
            )
        }
    }
    pub fn device_authority_observe(
        &mut self,
        origin: &str,
        remote: Option<SignedDeviceRoster>,
        server_time: i64,
    ) -> Result<Value> {
        self.device_authority_observe_at(origin, remote, server_time, current_time()?)
    }
    fn device_authority_observe_at(
        &mut self,
        origin: &str,
        remote: Option<SignedDeviceRoster>,
        server_time: i64,
        local: i64,
    ) -> Result<Value> {
        ensure!(valid_device_origin(origin), REJECTED);
        let mut authority = match &self.device_authority {
            Some(existing) => {
                existing.validate(self)?;
                ensure!(existing.origin == origin, REJECTED);
                existing.clone()
            }
            None => {
                ensure!(remote.is_none(), RESTORE);
                DeviceAuthorityState {
                    version: 1,
                    origin: origin.into(),
                    epoch: uuid::Uuid::new_v4().to_string(),
                    current: None,
                    pending: None,
                    allocated_version: 0,
                    allocated_device_id: 1,
                    issued_candidates: vec![],
                    observed_at: 0,
                    observed_hash: ZERO_HASH.into(),
                    last_clock: 0,
                    approval: None,
                }
            }
        };
        let now = clock(server_time, local, authority.last_clock)?;
        if let Some(roster) = &remote {
            verify_device_roster(roster)?;
            authority.matches_owner(self, &roster.roster)?;
            ensure!(roster.roster.issued_at <= now + DEVICE_TIME_SKEW, REJECTED);
        }
        let digest = roster_hash(remote.as_ref())?;
        let current_digest = roster_hash(authority.current.as_ref())?;
        if let Some(pending) = &authority.pending {
            if remote.is_some() && digest == checked(pending.change.roster.roster.digest())? {
                authority.finish()?;
            } else {
                ensure!(digest == current_digest, RESTORE);
                if pending.change.expires_at <= now {
                    authority.pending = None;
                    authority.approval = None;
                }
            }
        } else {
            ensure!(digest == current_digest, RESTORE);
        }
        authority.last_clock = now;
        authority.observed_at = now;
        authority.observed_hash = digest;
        let data = authority.data(now)?;
        self.device_authority = Some(authority);
        Ok(data)
    }
    pub fn device_authority_inspect(&self, code: &str, server_time: i64) -> Result<Value> {
        self.device_authority_inspect_at(code, server_time, current_time()?)
    }
    fn device_authority_inspect_at(
        &self,
        code: &str,
        server_time: i64,
        local: i64,
    ) -> Result<Value> {
        let authority = self
            .device_authority
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(REJECTED))?;
        authority.validate(self)?;
        let now = clock(server_time, local, authority.last_clock)?;
        let link = decode_code::<SignedDeviceLinkRequest>(LINK_PREFIX, code)?;
        self.validate_candidate(authority, &link, now)?;
        Ok(
            json!({"label":link.request.label,"device_id":authority.allocated_device_id+1,
            "identity_fingerprint":fingerprint(&link.request.identity_key)?,"request_hash":checked(link.request.digest())?,
            "expires_at":link.request.expires_at,"account_id":link.request.account_id,"root_epoch":link.request.root_epoch}),
        )
    }
    fn validate_candidate(
        &self,
        authority: &DeviceAuthorityState,
        link: &SignedDeviceLinkRequest,
        now: i64,
    ) -> Result<()> {
        verify_device_link(link)?;
        let request = &link.request;
        let current = authority
            .current
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(REJECTED))?;
        ensure!(
            request.valid_at(now)
                && current.roster.valid_at(now)
                && current.roster.devices.len() == 1
                && authority.allocated_device_id < MAX_DEVICE_ID
                && request.origin == authority.origin
                && request.account_id == self.account_id
                && request.root_epoch == authority.epoch
                && request.root_identity_key == self.upload.identity_key,
            REJECTED
        );
        let digest = checked(request.digest())?;
        ensure!(
            authority
                .issued_candidates
                .iter()
                .all(|issued| issued.request_id != request.request_id
                    && issued.request_hash != digest
                    && issued.identity_key != request.identity_key),
            REJECTED
        );
        Ok(())
    }
    pub async fn device_authority_prepare(
        &mut self,
        origin: &str,
        server_time: i64,
    ) -> Result<Value> {
        self.device_authority_propose(origin, server_time, None, None, None, current_time()?)
            .await
    }
    pub async fn device_authority_approve(
        &mut self,
        code: &str,
        expected_request_hash: &str,
        server_time: i64,
    ) -> Result<Value> {
        let link = decode_code::<SignedDeviceLinkRequest>(LINK_PREFIX, code)?;
        verify_device_link(&link)?;
        ensure!(
            checked(link.request.digest())? == expected_request_hash,
            REJECTED
        );
        let origin = link.request.origin.clone();
        self.device_authority_propose(
            &origin,
            server_time,
            Some(link),
            None,
            Some(expected_request_hash),
            current_time()?,
        )
        .await
    }
    pub async fn device_authority_revoke(
        &mut self,
        device_id: u8,
        server_time: i64,
    ) -> Result<Value> {
        let origin = self
            .device_authority
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(REJECTED))?
            .origin
            .clone();
        self.device_authority_propose(
            &origin,
            server_time,
            None,
            Some(device_id),
            None,
            current_time()?,
        )
        .await
    }
    async fn device_authority_propose(
        &mut self,
        origin: &str,
        server_time: i64,
        link: Option<SignedDeviceLinkRequest>,
        revoke: Option<u8>,
        expected_hash: Option<&str>,
        local: i64,
    ) -> Result<Value> {
        let mut authority = self
            .device_authority
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("device_authority_observe_required"))?
            .clone();
        authority.validate(self)?;
        ensure!(authority.origin == origin, REJECTED);
        let now = clock(server_time, local, authority.last_clock)?;
        if let Some(pending) = &authority.pending {
            ensure!(
                pending.change.valid_at(now),
                "device_authority_pending_expired"
            );
            if let Some(hash) = expected_hash {
                ensure!(
                    pending
                        .change
                        .link_request
                        .as_ref()
                        .is_some_and(|r| r.request.digest().is_ok_and(|h| h == hash)),
                    PENDING
                );
            } else {
                ensure!(link.is_none() && revoke.is_none(), PENDING);
            }
            let mut data = authority.data(now)?;
            data["change"] = serde_json::to_value(pending)?;
            return Ok(data);
        }
        authority.can_propose(now)?;
        let identity = self.identities.get_identity_key_pair().await?;
        ensure!(
            encode(identity.private_key().public_key()?.serialize()) == self.upload.identity_key,
            RESTORE
        );
        let mut devices = if let Some(current) = &authority.current {
            current.roster.devices.clone()
        } else {
            ensure!(link.is_none() && revoke.is_none(), REJECTED);
            let certificate = DeviceCertificate {
                account_id: self.account_id.clone(),
                root_epoch: authority.epoch.clone(),
                device_id: 1,
                identity_key: self.upload.identity_key.clone(),
                registration_id: self.upload.registration_id,
                label: "Primary phone".into(),
                request_hash: ZERO_HASH.into(),
            };
            vec![SignedDeviceCertificate {
                signature: sign(&identity, &checked(certificate.signing_bytes())?)?,
                certificate,
            }]
        };
        let mut highest = authority
            .current
            .as_ref()
            .map_or(1, |r| r.roster.highest_device_id);
        if let Some(link) = &link {
            self.validate_candidate(&authority, link, now)?;
            let request_hash = checked(link.request.digest())?;
            highest = authority
                .allocated_device_id
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!(REJECTED))?;
            let certificate = DeviceCertificate {
                account_id: self.account_id.clone(),
                root_epoch: authority.epoch.clone(),
                device_id: highest,
                identity_key: link.request.identity_key.clone(),
                registration_id: link.request.registration_id,
                label: link.request.label.clone(),
                request_hash: request_hash.clone(),
            };
            devices.push(SignedDeviceCertificate {
                signature: sign(&identity, &checked(certificate.signing_bytes())?)?,
                certificate,
            });
            authority.allocated_device_id = highest;
            authority.issued_candidates.push(IssuedCandidate {
                request_id: link.request.request_id.clone(),
                request_hash,
                identity_key: link.request.identity_key.clone(),
            });
        }
        if let Some(id) = revoke {
            ensure!(
                id > 1 && devices.iter().any(|d| d.certificate.device_id == id),
                REJECTED
            );
            devices.retain(|d| d.certificate.device_id != id);
        }
        let version = authority
            .allocated_version
            .checked_add(1)
            .filter(|v| *v <= MAX_SAFE_INTEGER)
            .ok_or_else(|| anyhow::anyhow!(REJECTED))?;
        let previous_hash = roster_hash(authority.current.as_ref())?;
        let roster = DeviceRoster {
            origin: origin.into(),
            account_id: self.account_id.clone(),
            root_epoch: authority.epoch.clone(),
            root_identity_key: self.upload.identity_key.clone(),
            version,
            previous_hash: previous_hash.clone(),
            highest_device_id: highest,
            issued_at: now,
            expires_at: now + DEVICE_ROSTER_LIFETIME,
            devices,
        };
        let signed_roster = SignedDeviceRoster {
            signature: sign(&identity, &checked(roster.signing_bytes())?)?,
            roster,
        };
        let change = DeviceChange {
            operation_id: uuid::Uuid::new_v4().to_string(),
            expires_at: link.as_ref().map_or(now + DEVICE_LINK_LIFETIME, |r| {
                r.request.expires_at.min(now + DEVICE_LINK_LIFETIME)
            }),
            expected_version: authority.current.as_ref().map_or(0, |r| r.roster.version),
            expected_roster_hash: previous_hash,
            roster: signed_roster,
            link_request: link,
        };
        let signed = SignedDeviceChange {
            signature: sign(&identity, &checked(change.signing_bytes())?)?,
            change,
        };
        authority.allocated_version = version;
        authority.pending = Some(signed.clone());
        authority.observed_at = 0;
        authority.last_clock = now;
        authority.approval = None;
        let mut data = authority.data(now)?;
        data["change"] = serde_json::to_value(signed)?;
        self.device_authority = Some(authority);
        Ok(data)
    }
    pub fn device_authority_commit(&mut self, receipt: DeviceAuthorityReceipt) -> Result<Value> {
        ensure!(!receipt.messaging_available, REJECTED);
        let mut authority = self
            .device_authority
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(REJECTED))?
            .clone();
        authority.validate(self)?;
        let pending = authority
            .pending
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(REJECTED))?;
        ensure!(
            receipt.operation_id == pending.change.operation_id
                && receipt.roster_version == pending.change.roster.roster.version
                && receipt.roster_hash == checked(pending.change.roster.roster.digest())?,
            REJECTED
        );
        authority.finish()?;
        let data = authority.data(current_time()?)?;
        self.device_authority = Some(authority);
        Ok(data)
    }
}

/// Separate CLI state: cannot deserialize as a v7 messaging State. Only this
/// newly generated device key is stored here; the phone's root key is public.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCandidate {
    version: u32,
    identity_pair: String,
    initial_roster: SignedDeviceRoster,
    pub request: SignedDeviceLinkRequest,
    approved: Option<SignedDeviceRoster>,
}
impl DeviceCandidate {
    pub fn create(
        initial_roster: SignedDeviceRoster,
        label: &str,
        expected_root_fingerprint: &str,
        now: i64,
    ) -> Result<Self> {
        ensure!(
            now.abs_diff(current_time()?) <= DEVICE_TIME_SKEW as u64,
            REJECTED
        );
        verify_device_roster(&initial_roster)?;
        let roster = &initial_roster.roster;
        ensure!(
            roster.valid_at(now)
                && fingerprint(&roster.root_identity_key)? == expected_root_fingerprint
                && roster.devices.len() == 1
                && roster.highest_device_id < MAX_DEVICE_ID
                && valid_device_label(label),
            REJECTED
        );
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let pair = IdentityKeyPair::generate(&mut rng);
        let mut nonce = [0; 32];
        rng.fill_bytes(&mut nonce);
        let request = DeviceLinkRequest {
            origin: roster.origin.clone(),
            account_id: roster.account_id.clone(),
            root_epoch: roster.root_epoch.clone(),
            root_identity_key: roster.root_identity_key.clone(),
            request_id: uuid::Uuid::new_v4().to_string(),
            identity_key: encode(pair.identity_key().serialize()),
            registration_id: rng.random_range(1..16380),
            label: label.into(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            issued_at: now,
            expires_at: now + DEVICE_LINK_LIFETIME,
        };
        let signed = SignedDeviceLinkRequest {
            signature: sign(&pair, &checked(request.signing_bytes())?)?,
            request,
        };
        Ok(Self {
            version: 1,
            identity_pair: encode(pair.serialize()),
            initial_roster,
            request: signed,
            approved: None,
        })
    }
    fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, REJECTED);
        verify_device_roster(&self.initial_roster)?;
        verify_device_link(&self.request)?;
        let pair = IdentityKeyPair::try_from(decode(&self.identity_pair)?.as_slice())?;
        ensure!(
            encode(pair.private_key().public_key()?.serialize())
                == self.request.request.identity_key
                && encode(pair.identity_key().serialize()) == self.request.request.identity_key
                && encode(pair.serialize()) == self.identity_pair
                && self.request.request.origin == self.initial_roster.roster.origin
                && self.request.request.account_id == self.initial_roster.roster.account_id
                && self.request.request.root_epoch == self.initial_roster.roster.root_epoch
                && self.request.request.root_identity_key
                    == self.initial_roster.roster.root_identity_key,
            REJECTED
        );
        if let Some(approved) = &self.approved {
            self.validate_approval(approved)?;
        }
        Ok(())
    }
    pub fn code(&self) -> Result<String> {
        self.validate()?;
        encode_code(LINK_PREFIX, &self.request)
    }
    pub fn accept(&mut self, code: &str, now: i64) -> Result<Value> {
        ensure!(
            now.abs_diff(current_time()?) <= DEVICE_TIME_SKEW as u64,
            REJECTED
        );
        self.validate()?;
        ensure!(self.request.request.valid_at(now), REJECTED);
        let approved = decode_code::<SignedDeviceRoster>(APPROVAL_PREFIX, code)?;
        self.validate_approval(&approved)?;
        ensure!(approved.roster.valid_at(now), REJECTED);
        if let Some(previous) = &self.approved {
            ensure!(previous == &approved, REJECTED);
        }
        self.approved = Some(approved);
        self.status()
    }
    fn validate_approval(&self, approved: &SignedDeviceRoster) -> Result<()> {
        verify_device_roster(approved)?;
        let r = &approved.roster;
        let q = &self.request.request;
        ensure!(
            r.origin == q.origin
                && r.account_id == q.account_id
                && r.root_epoch == q.root_epoch
                && r.root_identity_key == q.root_identity_key
                && r.version > self.initial_roster.roster.version,
            REJECTED
        );
        let certificate = &r
            .devices
            .last()
            .ok_or_else(|| anyhow::anyhow!(REJECTED))?
            .certificate;
        ensure!(
            r.devices.len() == 2
                && certificate.device_id > self.initial_roster.roster.highest_device_id
                && certificate.identity_key == q.identity_key
                && certificate.registration_id == q.registration_id
                && certificate.label == q.label
                && certificate.request_hash == checked(q.digest())?,
            REJECTED
        );
        Ok(())
    }
    pub fn status(&self) -> Result<Value> {
        self.validate()?;
        Ok(
            json!({"account_id":self.request.request.account_id,"label":self.request.request.label,
            "origin":self.request.request.origin,"root_fingerprint":fingerprint(&self.request.request.root_identity_key)?,
            "identity_fingerprint":fingerprint(&self.request.request.identity_key)?,"request_hash":checked(self.request.request.digest())?,
            "expires_at":self.request.request.expires_at,"approved":self.approved.is_some(),"messaging_available":false,
            "device_id":self.approved.as_ref().and_then(|r|r.roster.devices.last()).map(|d|d.certificate.device_id)}),
        )
    }
}

#[cfg(test)]
mod tests;
