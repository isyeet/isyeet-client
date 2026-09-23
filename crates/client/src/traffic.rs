//! Authenticated, bounded cover traffic. Nothing in this module changes relay
//! JSON or creates an automatic reply: receipts only ride later outgoing frames.
use super::*;
use std::collections::BTreeMap;

const TRAILER_BYTES: usize = 288;
const TRAILER_OFFSET: usize = PLAINTEXT_FRAME_BYTES - TRAILER_BYTES;
const TRAILER_MAGIC: &[u8; 16] = b"ISYEET-COVER-V1\0";
const CONSENT_SECONDS: i64 = 300;
const MAX_OUTSTANDING: usize = 8;
const MAX_PEERS: usize = 64;
const CREATION_BUDGET: usize = 4096;
const COVER_UNAVAILABLE: &str = "cover_unavailable";
const CLOCK_UNAVAILABLE: &str = "cover_clock_unavailable";

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct TrafficState {
    enabled: bool,
    #[serde(default)]
    clock_upper_bound: i64,
    #[serde(default)]
    confirmed_server_time: Option<i64>,
    peers: BTreeMap<String, Peer>,
    creations: Vec<i64>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Peer {
    fingerprint: String,
    advertised_at: i64,
    consent: bool,
    outstanding: Vec<Outstanding>,
    receipts: Vec<Receipt>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Outstanding {
    id: String,
    fingerprint: String,
    nonce: [u8; 32],
    expires_at: i64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Receipt {
    nonce: [u8; 32],
    expires_at: i64,
}
struct Trailer {
    enabled: bool,
    sent_at: i64,
    receipts: Vec<[u8; 32]>,
}

fn trailer(bytes: &[u8], expires_at: i64, current: i64, traffic_current: i64) -> Option<Trailer> {
    if bytes.len() != PLAINTEXT_FRAME_BYTES || !valid_deadline(expires_at, current) {
        return None;
    }
    let tail = &bytes[TRAILER_OFFSET..];
    if &tail[..16] != TRAILER_MAGIC || tail[16] > 1 || tail[25] > 8 {
        return None;
    }
    let sent_at = i64::from_be_bytes(tail[17..25].try_into().ok()?);
    if sent_at <= 0 || sent_at > traffic_current.saturating_add(MESSAGE_FUTURE_SKEW_SECONDS) {
        return None;
    }
    Some(Trailer {
        enabled: tail[16] == 1,
        sent_at,
        receipts: tail[26..26 + usize::from(tail[25]) * 32]
            .chunks_exact(32)
            .map(|nonce| nonce.try_into().expect("fixed nonce"))
            .collect(),
    })
}

impl State {
    pub fn cover_enabled(&self) -> bool {
        self.traffic.enabled
    }
    /// Caller must confirm the relay's account-wide quiet policy and persist
    /// this proposed state before advertising consent in any outgoing frame.
    pub fn set_traffic_mode(&mut self, enabled: bool) -> Result<()> {
        self.expire()?;
        self.traffic.enabled = enabled;
        if !enabled {
            self.traffic.confirmed_server_time = None;
        }
        self.prune_traffic(self.last_observed_at);
        Ok(())
    }
    /// Confirm a freshly fetched account policy which explicitly says cover is
    /// enabled. The caller measures the entire request's monotonic round trip,
    /// rounds it upward, and persists this state before releasing any packet.
    /// Server time is confined to traffic metadata, never plaintext retention.
    pub fn confirm_traffic_quiet(&mut self, server_time: i64, elapsed_seconds: i64) -> Result<()> {
        self.confirm_traffic_quiet_at(server_time, elapsed_seconds, current_time()?)
    }
    fn confirm_traffic_quiet_at(
        &mut self,
        server_time: i64,
        elapsed_seconds: i64,
        observed: i64,
    ) -> Result<()> {
        let current = observed.max(self.last_observed_at);
        ensure!(
            self.traffic.enabled
                && server_time > 0
                && (0..=60).contains(&elapsed_seconds)
                && server_time.abs_diff(current) <= MESSAGE_FUTURE_SKEW_SECONDS as u64,
            CLOCK_UNAVAILABLE
        );
        // The relay timestamp is floored to whole UTC seconds. One extra
        // second covers that quantization in addition to the full rounded RTT.
        let upper = server_time
            .checked_add(elapsed_seconds)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| anyhow::anyhow!(CLOCK_UNAVAILABLE))?;
        self.traffic.clock_upper_bound = self.traffic.clock_upper_bound.max(upper);
        self.traffic.confirmed_server_time = Some(server_time);
        self.prune_traffic(current);
        Ok(())
    }
    fn traffic_current(&self, local_current: i64) -> i64 {
        local_current.max(self.traffic.clock_upper_bound)
    }
    fn quiet_confirmation_fresh(&self, local_current: i64) -> bool {
        self.traffic.enabled
            && self.traffic.confirmed_server_time.is_some_and(|issued| {
                issued > 0
                    && issued.saturating_add(CONSENT_SECONDS) > self.traffic_current(local_current)
            })
    }
    pub fn cover_message_ids(&self) -> Vec<String> {
        self.traffic
            .peers
            .values()
            .flat_map(|peer| &peer.outstanding)
            .filter(|entry| self.outbox.iter().any(|message| message.id == entry.id))
            .map(|entry| entry.id.clone())
            .collect()
    }
    pub fn cover_candidates(&self) -> Vec<String> {
        let Ok(current) = current_time() else {
            return Vec::new();
        };
        self.cover_candidates_at(current.max(self.last_observed_at))
    }
    fn cover_candidates_at(&self, current: i64) -> Vec<String> {
        if !self.quiet_confirmation_fresh(current)
            || self.outbox.len() >= 16
            || !self.cover_message_ids().is_empty()
            || self.cover_budget(current) == 0
        {
            return Vec::new();
        }
        self.traffic
            .peers
            .iter()
            .filter(|(email, peer)| {
                self.fresh_consent(email, peer, current)
                    && peer
                        .outstanding
                        .iter()
                        .filter(|entry| entry.expires_at > current)
                        .count()
                        < MAX_OUTSTANDING
            })
            .map(|(email, _)| email.clone())
            .collect()
    }
    fn traffic_pin(&self, email: &str) -> Option<String> {
        if email == self.email || !self.verified.contains(email) {
            return None;
        }
        let pin = fingerprint(self.identities.known.get(email)?).ok()?;
        if self.group_identity_warnings.get(email) == Some(&pin) {
            return None;
        }
        Some(pin)
    }
    fn fresh_consent(&self, email: &str, peer: &Peer, current: i64) -> bool {
        let current = self.traffic_current(current);
        peer.consent
            && peer.advertised_at > 0
            && peer.advertised_at <= current.saturating_add(MESSAGE_FUTURE_SKEW_SECONDS)
            && peer.advertised_at.saturating_add(CONSENT_SECONDS) > current
            && self.traffic_pin(email).as_ref() == Some(&peer.fingerprint)
    }
    fn cover_budget(&self, current: i64) -> usize {
        CREATION_BUDGET.saturating_sub(
            self.traffic
                .creations
                .iter()
                .filter(|created| created.saturating_add(MESSAGE_LIFETIME_SECONDS) > current)
                .count(),
        )
    }
    pub(super) fn traffic_snapshot(&self) -> Value {
        let current = self.last_observed_at;
        json!({"enabled":self.traffic.enabled,"eligible_contacts":self.cover_candidates_at(current),
            "remaining_budget":self.cover_budget(current),"cover_outbox_ids":self.cover_message_ids(),
            "outstanding":self.traffic.peers.values().map(|peer| peer.outstanding.len()).sum::<usize>()})
    }
    pub async fn create_cover(&mut self, recipient: &str) -> Result<SendRequest> {
        self.create_cover_at(recipient, current_time()?).await
    }
    async fn create_cover_at(&mut self, recipient: &str, observed: i64) -> Result<SendRequest> {
        let mut proposed = self.clone();
        proposed.expire_at(observed)?;
        let recipient = normalized(recipient)?;
        let current = proposed.last_observed_at;
        ensure!(
            proposed.cover_candidates_at(current).contains(&recipient),
            COVER_UNAVAILABLE
        );
        let expires_at = deadline(current)?;
        let mut bytes = vec![0; PLAINTEXT_FRAME_BYTES];
        rand::rngs::OsRng.unwrap_err().fill_bytes(&mut bytes);
        bytes[..4].copy_from_slice(b"ISC1");
        bytes[4..12].copy_from_slice(&expires_at.to_be_bytes());
        let nonce: [u8; 32] = bytes[12..44].try_into()?;
        let message = proposed
            .encrypt_frame(&recipient, &bytes, expires_at)
            .await?;
        let peer = proposed
            .traffic
            .peers
            .get_mut(&recipient)
            .expect("eligible peer");
        peer.outstanding.push(Outstanding {
            id: message.id.clone(),
            fingerprint: peer.fingerprint.clone(),
            nonce,
            expires_at,
        });
        proposed.traffic.creations.push(current);
        *self = proposed;
        Ok(message)
    }
    pub(super) fn write_traffic_trailer(
        &self,
        recipient: &str,
        bytes: &mut [u8],
        _expires_at: i64,
    ) {
        if bytes.len() != PLAINTEXT_FRAME_BYTES {
            return;
        }
        let tail = &mut bytes[TRAILER_OFFSET..];
        // Unused receipt slots and reserved bytes remain random, just like the
        // padding replaced here. Only count-selected slots carry semantics.
        tail[..16].copy_from_slice(TRAILER_MAGIC);
        let current = self.traffic_current(self.last_observed_at);
        let enabled = self.quiet_confirmation_fresh(current);
        tail[16] = u8::from(enabled);
        // A queued real frame cannot mint or renew a future consent lease just
        // because its text deadline differs from the relay's quiet confirmation.
        let issued = if enabled {
            self.traffic
                .confirmed_server_time
                .expect("fresh confirmation")
        } else {
            current
        };
        tail[17..25].copy_from_slice(&issued.to_be_bytes());
        let receipts: Vec<_> = self
            .traffic
            .peers
            .get(recipient)
            .filter(|peer| self.traffic_pin(recipient).as_ref() == Some(&peer.fingerprint))
            .into_iter()
            .flat_map(|peer| &peer.receipts)
            .filter(|receipt| receipt.expires_at > self.last_observed_at)
            .take(8)
            .collect();
        tail[25] = receipts.len() as u8;
        for (index, receipt) in receipts.iter().enumerate() {
            tail[26 + index * 32..26 + (index + 1) * 32].copy_from_slice(&receipt.nonce);
        }
    }
    pub(super) fn learn_traffic(
        &mut self,
        sender: &str,
        bytes: &[u8],
        expires_at: i64,
        current: i64,
    ) {
        let Some(pin) = self.traffic_pin(sender) else {
            return;
        };
        let Some(trailer) = trailer(bytes, expires_at, current, self.traffic_current(current))
        else {
            return;
        };
        if !self.traffic.peers.contains_key(sender) && self.traffic.peers.len() >= MAX_PEERS {
            return;
        }
        let peer = self
            .traffic
            .peers
            .entry(sender.to_owned())
            .or_insert_with(|| Peer {
                fingerprint: pin.clone(),
                advertised_at: 0,
                consent: false,
                outstanding: Vec::new(),
                receipts: Vec::new(),
            });
        if peer.fingerprint != pin {
            peer.fingerprint = pin.clone();
            peer.advertised_at = 0;
            peer.consent = false;
            peer.receipts.clear();
        }
        // Equal-second disable wins, including across reordering and restart.
        if trailer.sent_at > peer.advertised_at
            || (trailer.sent_at == peer.advertised_at && !trailer.enabled)
        {
            peer.advertised_at = trailer.sent_at;
            peer.consent = trailer.enabled;
        }
        let acknowledged: BTreeSet<_> = peer
            .outstanding
            .iter()
            .filter(|entry| entry.fingerprint == pin && trailer.receipts.contains(&entry.nonce))
            .map(|entry| entry.id.clone())
            .collect();
        peer.outstanding
            .retain(|entry| !acknowledged.contains(&entry.id));
        // A peer's authenticated receipt can arrive before our HTTP completion.
        // Its already-received cover need not remain queued for another send.
        self.outbox
            .retain(|message| !acknowledged.contains(&message.id));
        self.prune_traffic(current);
    }
    pub(super) fn decode_cover(
        &mut self,
        bytes: &[u8],
        sender: &str,
        id: &str,
        current: i64,
    ) -> Result<LocalMessage> {
        ensure!(
            bytes.len() == PLAINTEXT_FRAME_BYTES && &bytes[..4] == b"ISC1",
            SECURITY_ALERT
        );
        let expires_at = i64::from_be_bytes(bytes[4..12].try_into()?);
        ensure!(valid_deadline(expires_at, current), SECURITY_ALERT);
        if expires_at > current {
            self.learn_traffic(sender, bytes, expires_at, current);
            if let Some(pin) = self.traffic_pin(sender)
                && (self.traffic.peers.contains_key(sender) || self.traffic.peers.len() < MAX_PEERS)
            {
                let peer = self
                    .traffic
                    .peers
                    .entry(sender.to_owned())
                    .or_insert_with(|| Peer {
                        fingerprint: pin.clone(),
                        advertised_at: 0,
                        consent: false,
                        outstanding: Vec::new(),
                        receipts: Vec::new(),
                    });
                if peer.fingerprint == pin {
                    let nonce = bytes[12..44].try_into()?;
                    if !peer.receipts.iter().any(|receipt| receipt.nonce == nonce) {
                        peer.receipts.push(Receipt { nonce, expires_at });
                        if peer.receipts.len() > 8 {
                            peer.receipts.remove(0);
                        }
                    }
                }
            }
        }
        Ok(LocalMessage {
            id: id.to_owned(),
            sender: sender.to_owned(),
            recipient: self.email.clone(),
            text: None,
            security_alert: None,
            duplicate: false,
            expires_at,
            expired: expires_at <= current,
            group_id: None,
            logical_id: None,
            sent_at: None,
            received_at: None,
            sender_fingerprint: None,
            status: None,
            accepted_count: None,
            recipient_count: None,
            deferred: false,
            cover: true,
        })
    }
    pub(super) fn invalidate_traffic_peer(&mut self, email: &str) {
        if let Some(peer) = self.traffic.peers.get_mut(email) {
            peer.consent = false;
            peer.receipts.clear();
            let ids: BTreeSet<_> = peer.outstanding.iter().map(|entry| &entry.id).collect();
            self.outbox.retain(|message| !ids.contains(&message.id));
        }
    }
    pub(super) fn prune_traffic(&mut self, current: i64) -> bool {
        let before = self.traffic.clone();
        let queued_before = self.cover_message_ids();
        let cancelled: BTreeSet<_> = self
            .traffic
            .peers
            .iter()
            .flat_map(|(email, peer)| {
                let cancel = !self.quiet_confirmation_fresh(current)
                    || !self.fresh_consent(email, peer, current);
                peer.outstanding
                    .iter()
                    .filter(move |entry| cancel || entry.expires_at <= current)
                    .map(|entry| entry.id.clone())
            })
            .collect();
        self.outbox
            .retain(|message| !cancelled.contains(&message.id));
        self.traffic
            .creations
            .retain(|created| created.saturating_add(MESSAGE_LIFETIME_SECONDS) > current);
        let pins: BTreeMap<_, _> = self
            .traffic
            .peers
            .keys()
            .filter_map(|email| self.traffic_pin(email).map(|pin| (email.clone(), pin)))
            .collect();
        self.traffic.peers.retain(|email, peer| {
            peer.outstanding.retain(|entry| entry.expires_at > current);
            peer.receipts.retain(|entry| entry.expires_at > current);
            // Reservations retain their captured identity across replacement;
            // new pins cannot acknowledge old covers or reset the eight-cover
            // allowance. Empty stale peer records expire to keep the cache bounded.
            !peer.outstanding.is_empty()
                || (pins.get(email) == Some(&peer.fingerprint)
                    && (!peer.receipts.is_empty()
                        || peer.advertised_at.saturating_add(MESSAGE_LIFETIME_SECONDS) > current))
        });
        before != self.traffic || queued_before != self.cover_message_ids()
    }
    pub(super) fn traffic_next_expiry(&self) -> Option<i64> {
        self.traffic
            .peers
            .values()
            .flat_map(|peer| {
                peer.outstanding
                    .iter()
                    .map(|entry| entry.expires_at)
                    .chain(peer.receipts.iter().map(|entry| entry.expires_at))
                    .chain(
                        (self.traffic.enabled && peer.consent)
                            .then_some(peer.advertised_at.saturating_add(CONSENT_SECONDS)),
                    )
            })
            .chain(
                self.traffic
                    .creations
                    .iter()
                    .map(|created| created.saturating_add(MESSAGE_LIFETIME_SECONDS)),
            )
            .chain(
                self.traffic
                    .confirmed_server_time
                    .filter(|_| self.traffic.enabled)
                    .map(|issued| issued.saturating_add(CONSENT_SECONDS)),
            )
            .filter(|expiry| *expiry > self.last_observed_at)
            .min()
    }
}

#[cfg(test)]
mod tests;
