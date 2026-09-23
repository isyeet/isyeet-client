//! Small immutable groups carried inside independently authenticated Signal legs.
//! The relay never receives a group descriptor or plaintext. Unknown roster
//! tokens are quarantined locally only after Signal authenticates the sender.
use super::*;
use std::collections::BTreeMap;

const MAX_GROUPS: usize = 32;
const MAX_DEFERRED: usize = 64;
const MAX_LOGICAL: usize = 4096;
const TOKEN_DOMAIN: &[u8] = b"ISYEET group member v1\0";
const GROUP_DOMAIN: &[u8] = b"ISYEET immutable group v1\0";
const ROW_DOMAIN: &[u8] = b"ISYEET local group row v1\0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMember {
    pub email: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub title: String,
    pub members: Vec<GroupMember>,
    pub blocked: bool,
    // Local lifecycle bookkeeping, never used as a message's send time.
    pub created_at: i64,
    nonce: [u8; 16],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboxRef {
    pub id: String,
    pub group_id: String,
    pub message_id: String,
    pub recipient: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct LogicalRecord {
    key: String,
    hash: String,
    pub expires_at: i64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct DeferredGroup {
    frame: String,
    transport_id: String,
    pub sender: String,
    fingerprint: String,
    received_at: i64,
    pub expires_at: i64,
    group_id: String,
}

struct ParsedGroup<'a> {
    id: String,
    title: String,
    nonce: [u8; 16],
    tokens: Vec<[u8; 32]>,
    logical_id: uuid::Uuid,
    expires_at: i64,
    text: &'a [u8],
    hash: String,
}
struct GroupReceipt<'a> {
    sender: &'a str,
    transport_id: &'a str,
    author: &'a str,
    received_at: i64,
    current: i64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex<const N: usize>(text: &str) -> Result<[u8; N]> {
    ensure!(
        text.len() == N * 2 && text.bytes().all(|b| b.is_ascii_hexdigit()),
        SECURITY_ALERT
    );
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)?;
    }
    Ok(bytes)
}
fn member_token(member: &GroupMember) -> Result<[u8; 32]> {
    ensure!(normalized(&member.email)? == member.email, SECURITY_ALERT);
    let mut hash = Sha256::new();
    hash.update(TOKEN_DOMAIN);
    hash.update((member.email.len() as u16).to_be_bytes());
    hash.update(member.email.as_bytes());
    hash.update(unhex::<32>(&member.fingerprint)?);
    Ok(hash.finalize().into())
}
fn group_id(nonce: &[u8; 16], title: &str, tokens: &[[u8; 32]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(GROUP_DOMAIN);
    hash.update(nonce);
    hash.update([title.len() as u8]);
    hash.update(title.as_bytes());
    hash.update([tokens.len() as u8]);
    for token in tokens {
        hash.update(token);
    }
    hash.finalize().into()
}
fn valid_title(title: &[u8]) -> bool {
    !title.is_empty() && title.len() <= 48 && title.iter().all(|b| (0x20..=0x7e).contains(b))
}
fn sorted_tokens(members: &[GroupMember]) -> Result<Vec<[u8; 32]>> {
    let mut tokens = members
        .iter()
        .map(member_token)
        .collect::<Result<Vec<_>>>()?;
    tokens.sort_unstable();
    ensure!(
        tokens.windows(2).all(|pair| pair[0] < pair[1]),
        SECURITY_ALERT
    );
    Ok(tokens)
}
fn group_frame(group: &Group, logical: uuid::Uuid, expires_at: i64, text: &str) -> Result<Vec<u8>> {
    ensure!(
        valid_text(text.as_bytes()),
        "Only 1-1024 printable ASCII bytes are accepted."
    );
    ensure!(
        valid_title(group.title.as_bytes()) && (2..=8).contains(&group.members.len()),
        SECURITY_ALERT
    );
    let tokens = sorted_tokens(&group.members)?;
    let id = group_id(&group.nonce, &group.title, &tokens);
    ensure!(hex(&id) == group.id, SECURITY_ALERT);
    let mut bytes = vec![0; PLAINTEXT_FRAME_BYTES];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut bytes);
    bytes[..4].copy_from_slice(b"ISG1");
    bytes[4..12].copy_from_slice(&expires_at.to_be_bytes());
    bytes[12..28].copy_from_slice(logical.as_bytes());
    bytes[28..44].copy_from_slice(&group.nonce);
    bytes[44..76].copy_from_slice(&id);
    bytes[76] = group.title.len() as u8;
    bytes[77] = tokens.len() as u8;
    bytes[78..80].copy_from_slice(&(text.len() as u16).to_be_bytes());
    let mut offset = 80;
    bytes[offset..offset + group.title.len()].copy_from_slice(group.title.as_bytes());
    offset += group.title.len();
    for token in tokens {
        bytes[offset..offset + 32].copy_from_slice(&token);
        offset += 32;
    }
    bytes[offset..offset + text.len()].copy_from_slice(text.as_bytes());
    Ok(bytes)
}
fn parse_group(bytes: &[u8], current: i64) -> Result<ParsedGroup<'_>> {
    ensure!(
        bytes.len() == PLAINTEXT_FRAME_BYTES && &bytes[..4] == b"ISG1",
        SECURITY_ALERT
    );
    let expires_at = i64::from_be_bytes(bytes[4..12].try_into()?);
    ensure!(valid_deadline(expires_at, current), SECURITY_ALERT);
    let logical_id = uuid::Uuid::from_slice(&bytes[12..28])?;
    ensure!(
        logical_id.get_version_num() == 4 && logical_id.get_variant() == uuid::Variant::RFC4122,
        SECURITY_ALERT
    );
    let nonce = bytes[28..44].try_into()?;
    let title_len = bytes[76] as usize;
    let count = bytes[77] as usize;
    let text_len = u16::from_be_bytes(bytes[78..80].try_into()?) as usize;
    ensure!(
        (1..=48).contains(&title_len)
            && (2..=8).contains(&count)
            && (1..=MAX_TEXT_BYTES).contains(&text_len),
        SECURITY_ALERT
    );
    let title_bytes = &bytes[80..80 + title_len];
    ensure!(valid_title(title_bytes), SECURITY_ALERT);
    let mut offset = 80 + title_len;
    let mut tokens = Vec::with_capacity(count);
    for _ in 0..count {
        tokens.push(bytes[offset..offset + 32].try_into()?);
        offset += 32;
    }
    ensure!(
        tokens.windows(2).all(|pair| pair[0] < pair[1]),
        SECURITY_ALERT
    );
    let text = &bytes[offset..offset + text_len];
    ensure!(valid_text(text), SECURITY_ALERT);
    let title = String::from_utf8(title_bytes.to_vec())?;
    let id = group_id(&nonce, &title, &tokens);
    ensure!(id.as_slice() == &bytes[44..76], SECURITY_ALERT);
    Ok(ParsedGroup {
        id: hex(&id),
        title,
        nonce,
        tokens,
        logical_id,
        expires_at,
        text,
        hash: hex(&Sha256::digest(&bytes[..offset + text_len])),
    })
}
fn row_id(group: &str, sender: &str, author: &str, logical: uuid::Uuid) -> String {
    let mut hash = Sha256::new();
    hash.update(ROW_DOMAIN);
    hash.update(group.as_bytes());
    hash.update((sender.len() as u16).to_be_bytes());
    hash.update(sender.as_bytes());
    hash.update(author.as_bytes());
    hash.update(logical.as_bytes());
    let digest = hash.finalize();
    uuid::Uuid::from_slice(&digest[..16])
        .expect("fixed digest length")
        .to_string()
}
fn logical_key(group: &str, sender: &str, author: &str, logical: uuid::Uuid) -> String {
    format!("{group}:{}:{sender}:{author}:{logical}", sender.len())
}

impl State {
    fn group_member(&self, email: &str) -> Result<GroupMember> {
        let member = self.pinned_group_member(email)?;
        ensure!(
            self.group_identity_warnings.get(email) != Some(&member.fingerprint),
            "group_verification_required"
        );
        Ok(member)
    }
    fn pinned_group_member(&self, email: &str) -> Result<GroupMember> {
        let key = if email == self.email {
            &self.upload.identity_key
        } else {
            ensure!(self.verified.contains(email), "group_verification_required");
            self.identities
                .known
                .get(email)
                .ok_or_else(|| anyhow::anyhow!("group_verification_required"))?
        };
        Ok(GroupMember {
            email: email.to_owned(),
            fingerprint: fingerprint(key)?,
        })
    }
    fn group_is_current(&self, group: &Group) -> bool {
        !group.blocked
            && group.members.iter().all(|member| {
                self.group_member(&member.email)
                    .is_ok_and(|current| current == *member)
            })
    }
    pub fn create_group(&mut self, title: &str, members: &[String]) -> Result<Group> {
        let mut proposed = self.clone();
        proposed.expire()?;
        ensure!(
            valid_title(title.as_bytes()) && (1..=7).contains(&members.len()),
            "Invalid group title or members."
        );
        ensure!(
            proposed.groups.len() < MAX_GROUPS,
            "Group capacity reached."
        );
        let mut roster = vec![proposed.group_member(&proposed.email)?];
        let mut seen = BTreeSet::from([proposed.email.clone()]);
        for email in members {
            ensure!(
                normalized(email)? == *email && seen.insert(email.clone()),
                "Invalid group title or members."
            );
            roster.push(proposed.group_member(email)?);
        }
        roster.sort_by(|a, b| a.email.cmp(&b.email));
        let tokens = sorted_tokens(&roster)?;
        let mut nonce = [0; 16];
        rand::rngs::OsRng.unwrap_err().fill_bytes(&mut nonce);
        let group = Group {
            id: hex(&group_id(&nonce, title, &tokens)),
            title: title.to_owned(),
            members: roster,
            blocked: false,
            created_at: proposed.last_observed_at,
            nonce,
        };
        proposed.groups.insert(group.id.clone(), group.clone());
        *self = proposed;
        Ok(group)
    }
    pub async fn encrypt_group(&mut self, id: &str, text: &str) -> Result<Vec<SendRequest>> {
        self.encrypt_group_at(id, text, current_time()?).await
    }
    async fn encrypt_group_at(
        &mut self,
        id: &str,
        text: &str,
        current: i64,
    ) -> Result<Vec<SendRequest>> {
        let mut proposed = self.clone();
        proposed.expire_at(current)?;
        let group = proposed
            .groups
            .get(id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Unknown group."))?;
        ensure!(proposed.group_is_current(&group), "group_blocked");
        ensure!(
            group
                .members
                .iter()
                .any(|member| member.email == proposed.email),
            SECURITY_ALERT
        );
        let recipients: Vec<_> = group
            .members
            .iter()
            .filter(|member| member.email != proposed.email)
            .collect();
        ensure!(
            proposed.outbox.len() + recipients.len() <= 16,
            "Outbox full; retry pending messages first."
        );
        let expires_at = deadline(proposed.last_observed_at)?;
        let logical = uuid::Uuid::new_v4();
        let plaintext = group_frame(&group, logical, expires_at, text)?;
        let author = fingerprint(&proposed.upload.identity_key)?;
        let message_id = row_id(id, &proposed.email, &author, logical);
        let mut requests = Vec::new();
        for member in &recipients {
            let request = proposed
                .encrypt_frame(&member.email, &plaintext, expires_at)
                .await?;
            proposed.group_outbox.insert(
                request.id.clone(),
                OutboxRef {
                    id: request.id.clone(),
                    group_id: id.to_owned(),
                    message_id: message_id.clone(),
                    recipient: member.email.clone(),
                },
            );
            requests.push(request);
        }
        proposed.record(LocalMessage {
            id: message_id,
            sender: proposed.email.clone(),
            recipient: proposed.email.clone(),
            text: Some(text.to_owned()),
            security_alert: None,
            duplicate: false,
            expires_at,
            expired: false,
            group_id: Some(id.to_owned()),
            logical_id: Some(logical.to_string()),
            sent_at: Some(expires_at - MESSAGE_LIFETIME_SECONDS),
            received_at: None,
            sender_fingerprint: Some(author),
            status: Some("queued".into()),
            accepted_count: Some(0),
            recipient_count: Some(recipients.len() as u8),
            deferred: false,
            cover: false,
        });
        *self = proposed;
        Ok(requests)
    }
    pub fn block_groups_for_contact(&mut self, email: &str) -> Result<()> {
        self.block_groups_for_contact_if_pin(email, None)
    }
    pub fn block_groups_for_contact_if_pin(
        &mut self,
        email: &str,
        expected: Option<&str>,
    ) -> Result<()> {
        let email = normalized(email)?;
        ensure!(self.has_contact(&email), "Add the contact first.");
        let pin = fingerprint(self.identities.known.get(&email).expect("checked contact"))?;
        if let Some(expected) = expected {
            ensure!(
                expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_hexdigit()),
                SECURITY_ALERT
            );
            if expected.to_ascii_lowercase() != pin {
                return Ok(());
            }
        }
        self.invalidate_groups_for_peer(&email, &pin);
        Ok(())
    }
    pub(super) fn invalidate_groups_for_peer(&mut self, email: &str, pin: &str) {
        self.invalidate_traffic_peer(email);
        self.group_identity_warnings
            .insert(email.to_owned(), pin.to_owned());
        let mut ids = BTreeSet::new();
        for group in self.groups.values_mut() {
            if group
                .members
                .iter()
                .any(|member| member.email == email && member.fingerprint == pin)
            {
                group.blocked = true;
                ids.insert(group.id.clone());
            }
        }
        let cancelled: BTreeSet<_> = self
            .group_outbox
            .values()
            .filter(|leg| ids.contains(&leg.group_id))
            .map(|leg| leg.id.clone())
            .collect();
        self.outbox
            .retain(|message| !cancelled.contains(&message.id));
        self.group_outbox.retain(|id, _| !cancelled.contains(id));
        for message in &mut self.messages {
            if message.group_id.as_ref().is_some_and(|id| ids.contains(id))
                && matches!(
                    message.status.as_deref(),
                    Some("queued" | "partially_accepted")
                )
            {
                message.status = Some("cancelled".into());
            }
        }
        self.deferred_groups
            .retain(|entry| entry.sender != email && !ids.contains(&entry.group_id));
    }
    pub(super) fn drop_deferred_for_removed_member(
        &mut self,
        email: &str,
        pin: &str,
    ) -> Result<()> {
        let token = member_token(&GroupMember {
            email: email.to_owned(),
            fingerprint: pin.to_owned(),
        })?;
        self.deferred_groups.retain(|entry| {
            entry.sender != email
                && decode(&entry.frame)
                    .ok()
                    .and_then(|bytes| {
                        parse_group(&bytes, self.last_observed_at)
                            .ok()
                            .map(|parsed| !parsed.tokens.contains(&token))
                    })
                    .unwrap_or(false)
        });
        Ok(())
    }
    fn resolve_tokens(&self, tokens: &[[u8; 32]]) -> Result<Option<Vec<GroupMember>>> {
        let mut known = BTreeMap::new();
        for email in std::iter::once(&self.email).chain(self.verified.iter()) {
            let Ok(member) = self.group_member(email) else {
                continue;
            };
            ensure!(
                known.insert(member_token(&member)?, member).is_none(),
                SECURITY_ALERT
            );
        }
        let mut members = Vec::new();
        for token in tokens {
            let Some(member) = known.get(token) else {
                return Ok(None);
            };
            members.push(member.clone());
        }
        members.sort_by(|a, b| a.email.cmp(&b.email));
        Ok(Some(members))
    }
    fn group_message(
        &mut self,
        bytes: &[u8],
        receipt: GroupReceipt<'_>,
        resolving: bool,
    ) -> Result<LocalMessage> {
        let GroupReceipt {
            sender,
            transport_id,
            author,
            received_at,
            current,
        } = receipt;
        let parsed = parse_group(bytes, current)?;
        let own_token = member_token(&self.group_member(&self.email)?)?;
        let author_token = member_token(&GroupMember {
            email: sender.to_owned(),
            fingerprint: author.to_owned(),
        })?;
        ensure!(
            parsed.tokens.contains(&own_token)
                && parsed.tokens.contains(&author_token)
                && sender != self.email,
            SECURITY_ALERT
        );
        let mut message = LocalMessage {
            id: row_id(&parsed.id, sender, author, parsed.logical_id),
            sender: sender.to_owned(),
            recipient: self.email.clone(),
            text: None,
            security_alert: None,
            duplicate: false,
            expires_at: parsed.expires_at,
            expired: parsed.expires_at <= current,
            group_id: Some(parsed.id.clone()),
            logical_id: Some(parsed.logical_id.to_string()),
            sent_at: Some(parsed.expires_at - MESSAGE_LIFETIME_SECONDS),
            received_at: Some(received_at),
            sender_fingerprint: Some(author.to_owned()),
            status: Some("received".into()),
            accepted_count: None,
            recipient_count: None,
            deferred: false,
            cover: false,
        };
        if message.expired {
            return Ok(message);
        }
        if let Some(group) = self.groups.get(&parsed.id) {
            ensure!(
                self.group_is_current(group)
                    && group.title == parsed.title
                    && group.nonce == parsed.nonce
                    && sorted_tokens(&group.members)? == parsed.tokens,
                SECURITY_ALERT
            );
        } else {
            ensure!(self.groups.len() < MAX_GROUPS, SECURITY_ALERT);
        }
        let key = logical_key(&parsed.id, sender, author, parsed.logical_id);
        if let Some(previous) = self.logical_received.iter().find(|entry| entry.key == key) {
            ensure!(previous.hash == parsed.hash, SECURITY_ALERT);
            if !resolving {
                message.duplicate = true;
                return Ok(message);
            }
        }
        let members = self.resolve_tokens(&parsed.tokens)?;
        if members.is_none() && !resolving {
            ensure!(self.deferred_groups.len() < MAX_DEFERRED, SECURITY_ALERT);
        }
        if !resolving {
            self.logical_received.push(LogicalRecord {
                key,
                hash: parsed.hash,
                expires_at: deadline(current)?,
            });
            if self.logical_received.len() > MAX_LOGICAL {
                self.logical_received.remove(0);
            }
        }
        let Some(members) = members else {
            if !resolving {
                self.deferred_groups.push(DeferredGroup {
                    frame: encode(bytes),
                    transport_id: transport_id.to_owned(),
                    sender: sender.to_owned(),
                    fingerprint: author.to_owned(),
                    received_at,
                    expires_at: parsed.expires_at,
                    group_id: parsed.id,
                });
            }
            message.id = transport_id.to_owned();
            message.group_id = None;
            message.logical_id = None;
            message.status = None;
            message.deferred = true;
            return Ok(message);
        };
        self.groups.entry(parsed.id.clone()).or_insert(Group {
            id: parsed.id,
            title: parsed.title,
            nonce: parsed.nonce,
            members,
            blocked: false,
            created_at: current,
        });
        message.text = Some(String::from_utf8(parsed.text.to_vec())?);
        Ok(message)
    }
    pub(super) fn decode_group(
        &mut self,
        bytes: &[u8],
        sender: &str,
        id: &str,
        current: i64,
    ) -> Result<LocalMessage> {
        let author = self.group_member(sender)?.fingerprint;
        self.group_message(
            bytes,
            GroupReceipt {
                sender,
                transport_id: id,
                author: &author,
                received_at: current,
                current,
            },
            false,
        )
    }
    pub(super) fn resolve_deferred_groups(&mut self, current: i64) -> Result<()> {
        let pending = std::mem::take(&mut self.deferred_groups);
        for entry in pending {
            if entry.expires_at <= current
                || !self
                    .group_member(&entry.sender)
                    .is_ok_and(|member| member.fingerprint == entry.fingerprint)
            {
                continue;
            }
            let result = decode(&entry.frame)
                .map_err(anyhow::Error::from)
                .and_then(|bytes| {
                    self.group_message(
                        &bytes,
                        GroupReceipt {
                            sender: &entry.sender,
                            transport_id: &entry.transport_id,
                            author: &entry.fingerprint,
                            received_at: entry.received_at,
                            current,
                        },
                        true,
                    )
                });
            match result {
                Ok(message) if message.deferred => self.deferred_groups.push(entry),
                Ok(message) if !message.expired && !message.duplicate => {
                    self.resolved_message_ids.push(message.id.clone());
                    self.record(message);
                }
                _ => {}
            }
        }
        let mut seen = BTreeSet::new();
        self.resolved_message_ids.retain(|id| {
            self.messages.iter().any(|message| &message.id == id) && seen.insert(id.clone())
        });
        Ok(())
    }
    pub(super) fn retire_groups(&mut self, current: i64) {
        let blocked_still_resolvable: BTreeSet<_> = self
            .groups
            .values()
            .filter(|group| {
                group.blocked
                    && group.members.iter().all(|member| {
                        self.pinned_group_member(&member.email)
                            .is_ok_and(|pin| pin == *member)
                    })
            })
            .map(|group| group.id.clone())
            .collect();
        self.groups.retain(|id, group| {
            blocked_still_resolvable.contains(id)
                || group.created_at.saturating_add(MESSAGE_LIFETIME_SECONDS) > current
                || self
                    .messages
                    .iter()
                    .any(|message| message.group_id.as_ref() == Some(id))
                || self.group_outbox.values().any(|leg| &leg.group_id == id)
                || self
                    .deferred_groups
                    .iter()
                    .any(|entry| &entry.group_id == id)
        });
    }
    pub(super) fn next_expiry(&self) -> Option<i64> {
        self.messages
            .iter()
            .map(|message| message.expires_at)
            .chain(self.outbox.iter().map(|message| message.expires_at))
            .chain(self.deferred_groups.iter().map(|entry| entry.expires_at))
            .chain(self.traffic_next_expiry())
            .filter(|expiry| *expiry > self.last_observed_at)
            .min()
    }
}

#[cfg(test)]
mod tests;
