//! Explicit local contact removal. Retired pins are rejection metadata, never trust.
use super::*;

pub(super) const REMOVAL_REJECTED: &str =
    "Contact removal rejected; existing contact remains unchanged.";
const MAX_REMOVED: usize = 256;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct RemovedContact {
    account_id: String,
    fingerprint: String,
    expires_at: i64,
    unsafe_identity: bool,
}

impl State {
    /// Persist before synchronizing the reduced relay allowlist. Already released
    /// ciphertext cannot be recalled by a local state transition.
    pub fn remove_contact(
        &mut self,
        account_id: &str,
        previous_fingerprint: &str,
    ) -> Result<Value> {
        let removal = (|| {
            let target = normalized(account_id)?;
            ensure!(target == account_id && target != self.account_id);
            let key = self
                .identities
                .known
                .get(&target)
                .ok_or_else(|| anyhow::anyhow!(REMOVAL_REJECTED))?;
            let pin = fingerprint(key)?;
            ensure!(
                previous_fingerprint.len() == 64
                    && previous_fingerprint
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                    && previous_fingerprint.to_ascii_lowercase() == pin
            );
            let mut proposed = self.clone();
            proposed.expire_at_with_resolution(current_time()?, false)?;
            ensure!(proposed.removed_contacts.len() < MAX_REMOVED);
            let unsafe_identity = proposed.group_identity_warnings.get(&target) == Some(&pin);
            proposed.invalidate_groups_for_peer(&target, &pin);
            if !unsafe_identity {
                proposed.group_identity_warnings.remove(&target);
            }
            proposed.sessions.0.remove(&target);
            proposed.identities.known.remove(&target);
            proposed.contact_usernames.remove(&target);
            proposed.verified.remove(&target);
            proposed
                .outbox
                .retain(|message| message.recipient != target);
            proposed.messages.retain(|message| {
                message.group_id.is_some()
                    || (message.sender != target && message.recipient != target)
            });
            proposed.drop_deferred_for_removed_member(&target, &pin)?;
            // Own account prekeys and consumed-key replay markers are shared
            // across contacts and must not be reset when one peer is removed.
            proposed.removed_contacts.push(RemovedContact {
                account_id: target.clone(),
                fingerprint: pin,
                expires_at: deadline(proposed.last_observed_at)?
                    .checked_add(MESSAGE_FUTURE_SKEW_SECONDS)
                    .ok_or_else(|| anyhow::anyhow!(REMOVAL_REJECTED))?,
                unsafe_identity,
            });
            proposed
                .resolved_message_ids
                .retain(|id| proposed.messages.iter().any(|message| &message.id == id));
            Ok::<_, anyhow::Error>((proposed, json!({"account_id":target,"removed":true})))
        })()
        .map_err(|_| anyhow::anyhow!(REMOVAL_REJECTED))?;
        *self = removal.0;
        Ok(removal.1)
    }

    pub(super) fn removed_pin(&self, account_id: &str, pin: &str) -> bool {
        self.removed_contacts.iter().any(|removed| {
            removed.unsafe_identity
                && removed.account_id == account_id
                && removed.fingerprint == pin
        })
    }

    pub(super) fn removed_delivery(&self, sender: &str, envelope: &str) -> bool {
        if sender == self.account_id
            || !self
                .removed_contacts
                .iter()
                .any(|removed| removed.account_id == sender)
        {
            return false;
        }
        if !self.has_contact(sender) {
            return true;
        }
        // The retired identity is visible in a PreKey envelope. Reject it before
        // Signal can touch stores or convert it into a warning about the new pin.
        // This is rejection only; no metadata here authenticates message content.
        let Ok(bytes) = decode(envelope) else {
            return false;
        };
        if bytes.len() != ENVELOPE_BYTES || bytes[0] != 1 || bytes[1] != 3 {
            return false;
        }
        let len = u32::from_be_bytes(bytes[2..6].try_into().expect("fixed header")) as usize;
        if len == 0 || len > ENVELOPE_BYTES - 6 {
            return false;
        }
        let Ok(message) = PreKeySignalMessage::try_from(&bytes[6..6 + len]) else {
            return false;
        };
        fingerprint(&encode(message.identity_key().serialize())).is_ok_and(|pin| {
            self.identities
                .known
                .get(sender)
                .and_then(|key| fingerprint(key).ok())
                .as_ref()
                != Some(&pin)
                && self
                    .removed_contacts
                    .iter()
                    .any(|removed| removed.account_id == sender && removed.fingerprint == pin)
        })
    }

    pub(super) fn prune_removed_contacts(&mut self, current: i64) -> bool {
        let before = (
            self.removed_contacts.len(),
            self.group_identity_warnings.len(),
        );
        self.removed_contacts
            .retain(|removed| removed.expires_at > current || removed.unsafe_identity);
        // Active warnings and blocked rosters remain; absent expired tombstones
        // do not grow indefinitely as the user cycles through contacts.
        self.group_identity_warnings.retain(|account_id, pin| {
            self.identities.known.contains_key(account_id)
                || self
                    .removed_contacts
                    .iter()
                    .any(|removed| &removed.account_id == account_id && &removed.fingerprint == pin)
                || self.groups.values().any(|group| {
                    group.members.iter().any(|member| {
                        &member.account_id == account_id && &member.fingerprint == pin
                    })
                })
        });
        before
            != (
                self.removed_contacts.len(),
                self.group_identity_warnings.len(),
            )
    }

    pub(super) fn verified_readded_contact(&mut self, account_id: &str, pin: &str) {
        for removed in &mut self.removed_contacts {
            if removed.account_id == account_id && removed.fingerprint != pin {
                removed.unsafe_identity = false;
            }
        }
        if self
            .group_identity_warnings
            .get(account_id)
            .is_some_and(|old| old != pin)
        {
            self.group_identity_warnings.remove(account_id);
        }
        self.prune_removed_contacts(self.last_observed_at);
    }
}

#[cfg(test)]
mod tests;
