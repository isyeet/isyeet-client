//! Durable, bounded public-prekey maintenance. The caller saves every proposal
//! before publishing it; a retry uses the exact saved operation and private keys.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

const CHECK_SECONDS: i64 = 3600;
const ROTATION_SECONDS: i64 = 30 * 86400;
// Pending libsignal setup can last 30 days, then ciphertext can queue 7 days.
const RETENTION_SECONDS: i64 = 45 * 86400;
const MAX_EC_RECORDS: usize = 4096;
const MAX_SIGNED_RECORDS: usize = 8;
const REJECTED: &str = "key_maintenance_rejected";

#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct KeyMaintenanceState {
    #[serde(default)]
    initial_upload_pending: bool,
    generation: Option<u32>,
    next_check_at: i64,
    rotated_at: i64,
    next_ec: u32,
    next_signed: u32,
    next_kyber: u32,
    pending: Option<KeyMaintenanceRequest>,
    #[serde(default)]
    pending_existing: Vec<PublicPreKey>,
    retired_ec: BTreeMap<u32, i64>,
    retired_signed: BTreeMap<u32, i64>,
    retired_kyber: BTreeMap<u32, i64>,
}
impl KeyMaintenanceState {
    pub(super) fn new(current: i64) -> Self {
        Self {
            initial_upload_pending: true,
            rotated_at: current,
            ..Self::default()
        }
    }
}
fn same<T: Serialize>(a: &T, b: &T) -> Result<bool> {
    Ok(serde_json::to_value(a)? == serde_json::to_value(b)?)
}
fn next_id(maximum: Option<u32>) -> Result<u32> {
    maximum
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!(REJECTED))
}
impl State {
    pub fn initial_upload_pending(&self) -> bool {
        self.key_maintenance.initial_upload_pending
    }
    pub fn confirm_initial_upload(&mut self) -> Result<()> {
        let mut proposed = self.clone();
        proposed.expire()?;
        ensure!(proposed.key_maintenance.pending.is_none(), REJECTED);
        proposed.key_maintenance.initial_upload_pending = false;
        *self = proposed;
        Ok(())
    }
    /// Check a fresh login against only this device's known public material.
    /// This never adopts a server identity or unjournaled rotation.
    pub fn validate_registered_keys(&self, keys: &KeyUpload) -> Result<()> {
        ensure!(
            keys.identity_key == self.upload.identity_key
                && keys.registration_id == self.upload.registration_id
                && keys.pre_keys.len() <= 100,
            REJECTED
        );
        let pair_matches = |expected: &KeyUpload| {
            keys.signed_pre_key == expected.signed_pre_key
                && keys.kyber_pre_key == expected.kyber_pre_key
        };
        ensure!(
            pair_matches(&self.upload)
                || self
                    .key_maintenance
                    .pending
                    .as_ref()
                    .is_some_and(|p| pair_matches(&p.keys)),
            REJECTED
        );
        let mut known: BTreeMap<u32, &str> = self
            .upload
            .pre_keys
            .iter()
            .map(|k| (k.id, k.public_key.as_str()))
            .collect();
        if let Some(pending) = &self.key_maintenance.pending {
            for key in pending
                .keys
                .pre_keys
                .iter()
                .chain(&self.key_maintenance.pending_existing)
            {
                known.insert(key.id, &key.public_key);
            }
        }
        let mut seen = BTreeSet::new();
        ensure!(
            keys.pre_keys.iter().all(|key| seen.insert(key.id)
                && known
                    .get(&key.id)
                    .is_some_and(|value| *value == key.public_key)),
            REJECTED
        );
        Ok(())
    }
    pub fn key_maintenance_due(&self) -> Result<bool> {
        Ok(self.key_maintenance.pending.is_some()
            || self.key_maintenance.next_check_at <= current_time()?.max(self.last_observed_at))
    }
    pub fn pending_key_maintenance(&self) -> Option<KeyMaintenanceRequest> {
        self.key_maintenance.pending.clone()
    }
    pub(super) fn key_maintenance_snapshot(&self) -> Value {
        json!({"initial_upload_pending":self.key_maintenance.initial_upload_pending,"pending":self.key_maintenance.pending,"next_check_at":self.key_maintenance.next_check_at})
    }
    pub(super) fn prune_key_material(&mut self, current: i64) -> Result<bool> {
        let meta = &mut self.key_maintenance;
        ensure!(
            self.prekeys.0.len() <= MAX_EC_RECORDS
                && self.signed.0.len() <= MAX_SIGNED_RECORDS
                && self.kyber.records.len() <= MAX_SIGNED_RECORDS
                && meta.retired_ec.len() <= MAX_EC_RECORDS
                && meta.retired_signed.len() <= MAX_SIGNED_RECORDS
                && meta.retired_kyber.len() <= MAX_SIGNED_RECORDS
                && meta.pending_existing.len() <= 100,
            REJECTED
        );
        let mut changed = false;
        if meta.next_ec == 0 {
            meta.next_ec = next_id(
                self.prekeys
                    .0
                    .keys()
                    .copied()
                    .chain(self.upload.pre_keys.iter().map(|key| key.id))
                    .max(),
            )?;
            meta.next_signed = next_id(
                self.signed
                    .0
                    .keys()
                    .copied()
                    .chain([self.upload.signed_pre_key.id])
                    .max(),
            )?;
            meta.next_kyber = next_id(
                self.kyber
                    .records
                    .keys()
                    .copied()
                    .chain([self.upload.kyber_pre_key.id])
                    .max(),
            )?;
            changed = true;
        }
        for id in meta
            .retired_ec
            .iter()
            .filter(|(_, until)| **until <= current)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>()
        {
            self.prekeys.0.remove(&id);
            meta.retired_ec.remove(&id);
            changed = true;
        }
        for id in meta
            .retired_signed
            .iter()
            .filter(|(_, until)| **until <= current)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>()
        {
            ensure!(id != self.upload.signed_pre_key.id, REJECTED);
            self.signed.0.remove(&id);
            meta.retired_signed.remove(&id);
            changed = true;
        }
        for id in meta
            .retired_kyber
            .iter()
            .filter(|(_, until)| **until <= current)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>()
        {
            ensure!(id != self.upload.kyber_pre_key.id, REJECTED);
            self.kyber.records.remove(&id);
            self.kyber
                .used
                .retain(|entry| !entry.starts_with(&format!("{id}:")));
            meta.retired_kyber.remove(&id);
            changed = true;
        }
        let previous = meta.retired_ec.len();
        meta.retired_ec
            .retain(|id, _| self.prekeys.0.contains_key(id));
        Ok(changed || previous != meta.retired_ec.len())
    }
    pub async fn prepare_key_maintenance(
        &mut self,
        inventory: isyeet_wire::KeyMaintenanceState,
    ) -> Result<Option<KeyMaintenanceRequest>> {
        self.prepare_key_maintenance_at(inventory, current_time()?)
            .await
    }
    async fn prepare_key_maintenance_at(
        &mut self,
        inventory: isyeet_wire::KeyMaintenanceState,
        observed: i64,
    ) -> Result<Option<KeyMaintenanceRequest>> {
        let mut proposed = self.clone();
        proposed.expire_at(observed)?;
        ensure!(!proposed.initial_upload_pending(), REJECTED);
        let current = proposed.last_observed_at;
        if let Some(pending) = &proposed.key_maintenance.pending {
            // Never reinterpret a fresh inventory while a durable operation is
            // uncertain. Its idempotent receipt must be retried first.
            return Ok(Some(pending.clone()));
        }
        ensure!(
            inventory.keys.identity_key == proposed.upload.identity_key
                && inventory.keys.registration_id == proposed.upload.registration_id
                && same(
                    &inventory.keys.signed_pre_key,
                    &proposed.upload.signed_pre_key
                )?
                && same(
                    &inventory.keys.kyber_pre_key,
                    &proposed.upload.kyber_pre_key
                )?
                && proposed
                    .key_maintenance
                    .generation
                    .is_none_or(|v| v == inventory.generation)
                && inventory.keys.pre_keys.len() <= 100,
            REJECTED
        );
        let mut present = BTreeSet::new();
        for key in &inventory.keys.pre_keys {
            ensure!(
                present.insert(key.id)
                    && !proposed.key_maintenance.retired_ec.contains_key(&key.id),
                REJECTED
            );
            let record = proposed
                .prekeys
                .get_pre_key(key.id.into())
                .await
                .map_err(|_| anyhow::anyhow!(REJECTED))?;
            ensure!(
                encode(record.public_key()?.serialize()) == key.public_key,
                REJECTED
            );
        }
        let until = current
            .checked_add(RETENTION_SECONDS)
            .ok_or_else(|| anyhow::anyhow!(REJECTED))?;
        for id in proposed.prekeys.0.keys().filter(|id| !present.contains(id)) {
            proposed
                .key_maintenance
                .retired_ec
                .entry(*id)
                .or_insert(until);
        }
        proposed.upload.pre_keys = inventory.keys.pre_keys.clone();
        proposed.key_maintenance.generation = Some(inventory.generation);
        proposed.key_maintenance.next_check_at = current
            .checked_add(CHECK_SECONDS)
            .ok_or_else(|| anyhow::anyhow!(REJECTED))?;
        let rotate = proposed.key_maintenance.rotated_at == 0
            || current.saturating_sub(proposed.key_maintenance.rotated_at) >= ROTATION_SECONDS;
        let additions = if present.len() < 16 {
            32 - present.len()
        } else {
            0
        };
        if !rotate && additions == 0 {
            *self = proposed;
            return Ok(None);
        }
        ensure!(
            inventory.generation < u32::MAX
                && proposed.prekeys.0.len() + additions <= MAX_EC_RECORDS
                && (!rotate
                    || (proposed.signed.0.len() < MAX_SIGNED_RECORDS
                        && proposed.kyber.records.len() < MAX_SIGNED_RECORDS)),
            REJECTED
        );
        let mut keys = proposed.upload.clone();
        keys.pre_keys.clear();
        let mut rng = rand::rngs::OsRng.unwrap_err();
        for _ in 0..additions {
            let id = proposed.key_maintenance.next_ec;
            proposed.key_maintenance.next_ec = next_id(Some(id))?;
            ensure!(!proposed.prekeys.0.contains_key(&id), REJECTED);
            let pair = KeyPair::generate(&mut rng);
            proposed
                .prekeys
                .save_pre_key(id.into(), &PreKeyRecord::new(id.into(), &pair))
                .await?;
            keys.pre_keys.push(PublicPreKey {
                id,
                public_key: encode(pair.public_key.serialize()),
            });
        }
        if rotate {
            let identity = proposed.identities.get_identity_key_pair().await?;
            let signed_id = proposed.key_maintenance.next_signed;
            let kyber_id = proposed.key_maintenance.next_kyber;
            proposed.key_maintenance.next_signed = next_id(Some(signed_id))?;
            proposed.key_maintenance.next_kyber = next_id(Some(kyber_id))?;
            ensure!(
                !proposed.signed.0.contains_key(&signed_id)
                    && !proposed.kyber.records.contains_key(&kyber_id),
                REJECTED
            );
            let pair = KeyPair::generate(&mut rng);
            let signature = identity
                .private_key()
                .calculate_signature(&pair.public_key.serialize(), &mut rng)?;
            let millis: u64 = current
                .checked_mul(1000)
                .ok_or_else(|| anyhow::anyhow!(REJECTED))?
                .try_into()?;
            let record = SignedPreKeyRecord::new(
                signed_id.into(),
                Timestamp::from_epoch_millis(millis),
                &pair,
                &signature,
            );
            proposed
                .signed
                .save_signed_pre_key(signed_id.into(), &record)
                .await?;
            let kem = KyberPreKeyRecord::generate(
                kem::KeyType::Kyber1024,
                kyber_id.into(),
                identity.private_key(),
            )?;
            proposed
                .kyber
                .save_kyber_pre_key(kyber_id.into(), &kem)
                .await?;
            keys.signed_pre_key = SignedPublicPreKey {
                id: signed_id,
                public_key: encode(pair.public_key.serialize()),
                signature: encode(signature),
            };
            keys.kyber_pre_key = SignedPublicPreKey {
                id: kyber_id,
                public_key: encode(kem.public_key()?.serialize()),
                signature: encode(kem.signature()?),
            };
        }
        let request = KeyMaintenanceRequest {
            operation_id: uuid::Uuid::new_v4().to_string(),
            expected_generation: inventory.generation,
            keys,
        };
        proposed.key_maintenance.pending = Some(request.clone());
        proposed.key_maintenance.pending_existing = inventory.keys.pre_keys;
        ensure!(
            serde_json::to_vec(&proposed)?.len() < MAX_STATE_BYTES - 65536,
            REJECTED
        );
        *self = proposed;
        Ok(Some(request))
    }
    pub fn confirm_key_maintenance(&mut self, receipt: KeyMaintenanceResponse) -> Result<()> {
        self.confirm_key_maintenance_at(receipt, current_time()?)
    }
    fn confirm_key_maintenance_at(
        &mut self,
        receipt: KeyMaintenanceResponse,
        observed: i64,
    ) -> Result<()> {
        let mut proposed = self.clone();
        proposed.expire_at(observed)?;
        let current = proposed.last_observed_at;
        let pending = proposed
            .key_maintenance
            .pending
            .take()
            .ok_or_else(|| anyhow::anyhow!(REJECTED))?;
        ensure!(
            receipt.operation_id == pending.operation_id
                && Some(receipt.generation) == pending.expected_generation.checked_add(1),
            REJECTED
        );
        if pending.keys.signed_pre_key.id != proposed.upload.signed_pre_key.id {
            let until = current
                .checked_add(RETENTION_SECONDS)
                .ok_or_else(|| anyhow::anyhow!(REJECTED))?;
            proposed
                .key_maintenance
                .retired_signed
                .insert(proposed.upload.signed_pre_key.id, until);
            proposed
                .key_maintenance
                .retired_kyber
                .insert(proposed.upload.kyber_pre_key.id, until);
            proposed.key_maintenance.rotated_at = current;
        }
        proposed.upload = pending.keys;
        proposed
            .upload
            .pre_keys
            .append(&mut proposed.key_maintenance.pending_existing);
        proposed.upload.pre_keys.sort_by_key(|key| key.id);
        proposed.key_maintenance.generation = Some(receipt.generation);
        proposed.key_maintenance.next_check_at = current
            .checked_add(CHECK_SECONDS)
            .ok_or_else(|| anyhow::anyhow!(REJECTED))?;
        *self = proposed;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
