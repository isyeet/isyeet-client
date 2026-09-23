//! Serialized libsignal stores. No private key or session data reaches the service.
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use libsignal_protocol::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    STANDARD.encode(bytes)
}
pub fn decode(s: &str) -> Result<Vec<u8>, SignalProtocolError> {
    STANDARD
        .decode(s)
        .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Identities {
    pub pair: String,
    pub registration: u32,
    pub known: BTreeMap<String, String>,
}
#[async_trait(?Send)]
impl IdentityKeyStore for Identities {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        IdentityKeyPair::try_from(decode(&self.pair)?.as_slice())
    }
    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.registration)
    }
    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let encoded = encode(identity.serialize());
        if let Some(old) = self.known.get(address.name()) {
            if old != &encoded {
                return Err(SignalProtocolError::UntrustedIdentity(address.clone()));
            }
        } else {
            if self.known.len() >= 64 {
                return Err(SignalProtocolError::InvalidArgument(
                    "contact limit reached".into(),
                ));
            }
            self.known.insert(address.name().to_string(), encoded);
        }
        Ok(IdentityChange::NewOrUnchanged)
    }
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _: Direction,
    ) -> Result<bool, SignalProtocolError> {
        Ok(self
            .known
            .get(address.name())
            .is_none_or(|v| v == &encode(identity.serialize())))
    }
    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        self.known
            .get(address.name())
            .map(|s| IdentityKey::decode(&decode(s)?))
            .transpose()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Sessions(pub BTreeMap<String, String>);
#[async_trait(?Send)]
impl SessionStore for Sessions {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        self.0
            .get(address.name())
            .map(|s| SessionRecord::deserialize(&decode(s)?))
            .transpose()
    }
    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0
            .insert(address.name().to_string(), encode(record.serialize()?));
        Ok(())
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct PreKeys(pub BTreeMap<u32, String>);
#[async_trait(?Send)]
impl PreKeyStore for PreKeys {
    async fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        PreKeyRecord::deserialize(&decode(
            self.0
                .get(&id.into())
                .ok_or(SignalProtocolError::InvalidPreKeyId)?,
        )?)
    }
    async fn save_pre_key(
        &mut self,
        id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0.insert(id.into(), encode(record.serialize()?));
        Ok(())
    }
    async fn remove_pre_key(&mut self, id: PreKeyId) -> Result<(), SignalProtocolError> {
        self.0.remove(&id.into());
        Ok(())
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SignedPreKeys(pub BTreeMap<u32, String>);
#[async_trait(?Send)]
impl SignedPreKeyStore for SignedPreKeys {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        SignedPreKeyRecord::deserialize(&decode(
            self.0
                .get(&id.into())
                .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?,
        )?)
    }
    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0.insert(id.into(), encode(record.serialize()?));
        Ok(())
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct KyberPreKeys {
    pub records: BTreeMap<u32, String>,
    pub used: BTreeSet<String>,
}
#[async_trait(?Send)]
impl KyberPreKeyStore for KyberPreKeys {
    async fn get_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        KyberPreKeyRecord::deserialize(&decode(
            self.records
                .get(&id.into())
                .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?,
        )?)
    }
    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.records.insert(id.into(), encode(record.serialize()?));
        Ok(())
    }
    async fn mark_kyber_pre_key_used(
        &mut self,
        id: KyberPreKeyId,
        ec: SignedPreKeyId,
        base: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        let key = format!("{id}:{ec}:{}", encode(base.serialize()));
        if self.used.contains(&key) || self.used.len() >= 8192 {
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "reused or exhausted last-resort prekey".into(),
            ));
        }
        self.used.insert(key);
        Ok(())
    }
}
