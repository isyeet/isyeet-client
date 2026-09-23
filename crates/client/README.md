# Shared client and local CLI

`isyeet-client` wraps the official Signal protocol implementation. `Cargo.toml`
pins the upstream commit; the workspace lockfile pins all resolved dependencies.
This integration is not independently audited and makes no vulnerability-free
claim. Both clients call the same protocol core; private keys never go to the
service. Verify identities by comparing fingerprints through an independent
trusted channel before either direction of messaging is enabled.

## Build

Install Rust 1.94+ and Protocol Buffers `protoc`, then from the repository root:

```sh
cargo build --locked -p isyeet-client
cargo test --locked -p isyeet-client
```

For the iOS static library exclude CLI dependencies:

```sh
cargo build --locked -p isyeet-client --lib --no-default-features --release --target aarch64-apple-ios
```

## Command line

All commands take global `--server URL --state PATH` options. The default server
is `http://127.0.0.1:8080` and default state is `isyeet-state.json`. HTTP is allowed
only for literal loopback IP addresses; all other services require HTTPS. The
state contains private keys, session credentials and recent plaintext messages;
keep it on an encrypted local disk, never in source control or cloud sync. Do
not restore old copies: rolling back a ratchet state is unsafe. One state per
account, one immutable device identity per Gmail or Google Workspace address.

```sh
# Browser-based Google OAuth Desktop sign-in. Configure the same client ID in
# the server's accepted audience list. Optional client secret can be in
# ISYEET_GOOGLE_CLIENT_SECRET instead of shell history.
isyeet --server https://service.example --state alice.json login --client-config /path/to/downloaded-desktop-client.json
# Or: login --client-id YOUR.apps.googleusercontent.com

# Only against an explicitly enabled development server on literal loopback:
isyeet --state alice.json dev-login alice@gmail.com
isyeet --state bob.json dev-login bob@gmail.com

isyeet --state alice.json fingerprint
isyeet --state bob.json fingerprint
isyeet --state alice.json add-contact bob@gmail.com
isyeet --state bob.json add-contact alice@gmail.com

# Supply the complete 64-hex fingerprint obtained directly from each person:
isyeet --state alice.json verify-contact bob@gmail.com --fingerprint BOBS_FINGERPRINT
isyeet --state bob.json verify-contact alice@gmail.com --fingerprint ALICES_FINGERPRINT

printf '%s' 'Hello Bob.' | isyeet --state alice.json send bob@gmail.com
isyeet --state bob.json receive
isyeet --state alice.json retry
isyeet --state bob.json history

# Test your own account through the same encrypted relay queue:
printf '%s' 'Self delivery test.' | isyeet --state alice.json send-self
isyeet --state alice.json receive
# Equivalent: send alice@gmail.com

# Every selected peer must already be independently verified:
isyeet --state alice.json create-group --title 'Project' bob@gmail.com carol@gmail.com
isyeet --state alice.json groups
printf '%s' 'Group text.' | isyeet --state alice.json send-group GROUP_ID
```

Groups have 2–8 immutable members including yourself, and a printable ASCII title
of 1–48 bytes. Every member must independently verify every other member before
group text can appear. Each message carries its full authenticated descriptor and
uses a separate existing Signal session for each recipient. The relay still sees
only ordinary fixed-size encrypted envelopes. A send commits every fanout leg
atomically, then retries each original ciphertext independently. A local status
of `relay_accepted` means the relay accepted the indicated envelopes; it does not
mean any recipient received or read the text. Partial acceptance reports counts.

Authenticated group messages containing an unknown or unverified member are held
in a bounded local quarantine, without displayed text. Save the returned state
before acknowledging the relay. Verification and maintenance resolve eligible
entries using the original receipt time and expiry; they never decrypt a Signal
ciphertext twice. A full quarantine or group capacity produces a generic rejected
message and ACK rather than blocking the relay queue. Unknown member addresses
cannot be recovered from the compact tokens: compare and verify members through
an independent channel. There are no invitations or automatic trust decisions.

An observed contact identity change permanently blocks affected stored groups and
cancels all their pending legs, including legs to unchanged members. Historical
group text retains its original identity metadata until expiry. A group warning
also prevents an undiscovered descriptor or quarantined text from trusting the
warned pin. Re-verifying the same old fingerprint does not clear that warning;
successful explicit different-key replacement does. Create a new group for the
new immutable roster.

`send-self` uses real Signal encryption and the normal durable relay delivery,
receive and acknowledgment paths. It needs no contact lookup or fingerprint
verification: the self identity comes only from the account's local private key.
Its separate sending/receiving sessions and dedicated locally generated prekeys
never consume the prekeys published for contacts. The relay cannot supply a
replacement self key. Initialization completes the two local Signal endpoints'
handshake using fixed internal setup bytes, so the session does not remain
unacknowledged and expire after 30 days. These setup bytes contain no user text
and are never displayed or sent to the relay. Sending creates only a ciphertext outbox entry; the text
appears once after authenticated receipt, with no local plaintext echo. The
normal ASCII restrictions, fixed padding, seven-day expiry, retries and duplicate
handling apply. Both endpoints of this test are on the same installation; it
does not verify another person's identity or link a second device.

`send --text TEXT` is also available but puts text in process arguments and
possibly shell history. Standard input must contain exactly 1–1024 printable
ASCII bytes. `receive` displays JSON records with literal text; no rich text,
link handling, terminal escapes or Unicode are rendered. Unverified contacts
stay queued and generate an alert until added and independently verified. The
server accepts a sender only after the recipient publishes its verified contact
list. Both people must independently verify each other before either can send.
The CLI publishes the list after durable verification and resynchronizes it on
login, send/retry, and receive, so a network failure cannot lose the decision.

If a contact explicitly re-enrolls with a new identity, obtain its new complete
fingerprint through an independent trusted channel. Find the old pinned
fingerprint with `contacts`, then remove the old contact before re-adding:

```sh
isyeet --state alice.json contacts
isyeet --state alice.json remove-contact bob@gmail.com --previous-fingerprint OLD_BOBS_FINGERPRINT
isyeet --state alice.json add-contact bob@gmail.com
isyeet --state alice.json verify-contact bob@gmail.com --fingerprint NEW_BOBS_FINGERPRINT
```

Removal requires the full current saved fingerprint so a stale confirmation
cannot remove a changed contact. It deletes that peer's local Signal session,
pin, verification, direct history and pending sends. Groups containing that pin
remain blocked; all remaining outgoing copies are cancelled, including copies
to other members. Existing group history keeps its original expiry. Hidden group
text containing the removed member is discarded. Own account prekeys, other
contacts and replay tracking are preserved. Already released ciphertext cannot
be recalled. The local removal is saved before publishing the reduced relay
allowlist; if publication fails, `retry` or `receive` resynchronizes it. Do not
repeat a removal already reported as saved.

A voluntary removal permits re-adding the same identity with new independent
verification. A pin previously warned about as changed is blocked until a
different identity is independently verified. At most 256 content-free retired
pin records prevent stale queued PreKey messages from reintroducing trust or
raising a warning against a newly verified identity. Normal records expire after
seven days plus the 60-second permitted clock skew; an unsafe pin remains blocked
until a different pin is verified. No live record is evicted to make room. Cover
consent and queued covers are cancelled; outstanding cover budget reservations
remain until their original expiry rather than being refunded by removal.
While a removed contact is absent, queued deliveries are generically rejected
and acknowledged after durable storage; they do not recreate the contact.

The former `replace-contact` CLI shortcut is retired and returns instructions
for this removal, re-addition and independent-verification flow. Ordinary
`add-contact` never replaces a saved pin. When receiving detects a changed
identity, the message remains queued and the CLI durably blocks that contact's
sending and retries; other contacts continue working.

Each command holds a file lock. Local state and lock files must be owned by the
user, regular files with mode 0600 and one hard link. State replacement writes a
new mode-0600 file, flushes its contents, renames it, then flushes the directory.
The outbox is committed before network send; retries reuse the same UUID and
ciphertext and original expiration deadline. Receiving commits plaintext, ratchet
and duplicate tracking before ACK. A failed save prevents send or ACK.

Messages expire seven days after the sender encrypts them, regardless of whether
they have been read or delivered. The deadline is authenticated inside the Signal
plaintext and repeated in the relay request. Retrying, receiving, restarting or
importing state never grants a new message lifetime. Every CLI command durably
prunes expired history and pending ciphertext before use, including offline
`history`, `contacts`, and `fingerprint` commands with expired authentication.
Each outbox attempt rechecks expiry. A stopped CLI cannot erase its file while it
is not running; the next invocation deletes expired entries before display or
network activity. Previously printed terminal output and copies made outside
ISYEET are outside this retention mechanism.

Upgrading version-1 state discards undated local messages and unsent ciphertext;
there is no trustworthy send time from which to calculate their age. Encryption
keys, established ratchets and verified contacts remain unchanged. Authenticated
legacy ISY1 messages are byte-validated, silently discarded and acknowledged.
The new ISY2 frame is exactly 2048 bytes: magic at 0..4, signed big-endian i64 UTC
expiration seconds at 4..12, big-endian u16 length at 12..14, printable ASCII at
14..14+length, and random padding. An implied send time more than 60 seconds ahead
of the receiver clock is rejected. The outer encrypted envelope stays 8192 bytes.
Current opaque state is version 6. Existing version-2 through version-5 state migrates without
changing keys, sessions, dated history or original pending deadlines. Older
clients reject version 6 rather than silently dropping group, warning, traffic, retired-pin or key-maintenance state.

## Automatic key maintenance

After initial registration, online clients check the relay key inventory at most
hourly. Fewer than 16 available EC one-time prekeys triggers a top-up to 32.
The signed EC and signed last-resort Kyber1024 prekeys rotate together every
30 days; the account identity and existing Signal sessions do not change.
Legacy state schedules its first rotation at the first successful maintenance
check. This uses the same pinned official libsignal generation and signatures.

A proposal contains the new private keys plus one exact public request with a
UUID and expected relay generation. Save it atomically **before** uploading.
Retry that saved request before fetching another inventory; a timeout never
regenerates keys, IDs or the request. Only its matching receipt commits the new
public baseline. The relay's generation check and latest-operation receipt
prevent retries from replenishing already consumed one-time keys.

An EC private key that disappears from a verified inventory is retained for
45 days from its first observed absence. Previous signed and Kyber private keys
are retained for 45 days from successful replacement confirmation. This covers
a pending Signal session of up to 30 days plus seven days of queued delivery,
with margin. Consumed EC private keys are removed by libsignal. Old Kyber replay
markers are discarded only with their retired Kyber key. The bounds are 4,096
EC private records and eight signed/Kyber epochs; reaching a bound rejects new
maintenance without evicting live keys. Receive processing continues before
maintenance so authenticated messages can consume one-time keys and free space.
This does not provide indefinite support for externally cached old bundles.

Freshly initialized state alone has `initial_upload_pending=true`. The exact
initial upload can be retried with its originally saved session. On a fresh OAuth
login to any existing state, check `/v1/keys/me` against `validate_registered_keys`
before adopting the new bearer. Only current or exactly journaled public keys
are accepted. A missing registration cannot cause automatic re-publication of
an old identity, even if an earlier initial-upload response was lost. A matching
registration confirms the lost initial response. If the account was deleted or
replaced, explicit local recovery is required; Google login cannot restore keys.

## Cover traffic

Notifications is the default mode. Cover mode is an explicit, mutually exclusive
choice: the host first confirms the relay's account-wide quiet policy, then
durably enables the core's mode before sending an advertisement. Disabling cover
stops new cover creation and deletes queued covers immediately; the host keeps
notifications quiet for the relay's seven-minute transition interval. The core
does not contact the relay, schedule timers, or enforce that external policy.
Before every Cover-mode send opportunity, including a real-message retry, the
host fetches the policy again, requires `cover:true`, and passes `server_time`
plus the ceiling of the complete monotonic request duration to
`confirm_traffic_quiet`. The duration must be 0–60 seconds and relay time must
be within 60 seconds of the local clock; otherwise cover is paused with
`cover_clock_unavailable`. Confirmation is persisted before selecting or
releasing an envelope. Enabling the local flag alone grants no advertisement
or cover eligibility. The mode-change flow can propose enable plus confirmation
and persist their final state atomically.

Updated clients advertise support and current consent in the authenticated
padding of ordinary direct, group and cover frames. Older direct/group parsers
ignore that padding and still validate the same ASCII text. A contact becomes
eligible only after a valid authenticated frame from its independently verified,
current identity advertises consent. Consent lasts five minutes from the relay
timestamp of the sender's last confirmed quiet policy, authenticated inside the
Signal frame, with a maximum 60-second future allowance when parsing the lease.
That timestamp is independent of the real text's original creation and expiry.
Receipt time and retries never refresh a lease. A newer disable
wins over older enables; disabling also wins a same-second tie. Missing or
malformed advertisements grant no consent and do not hide valid ASCII text.
After an idle interval, a fresh real exchange is needed to bootstrap consent.
The core stores a separate, nondecreasing traffic-time bound: relay timestamp
plus the rounded full round trip and one second for timestamp quantization.
The later of this bound and local time governs permission-lease freshness and
cancels queued covers whose permission has expired. Original seven-day receipt,
reservation and creation-budget deadlines use the retained local clock, so an
upper bound cannot release their allowances early. Relay time never advances
the human-message retention clock or prunes human history. Mode disable clears
the local quiet confirmation. A slow, inconsistent
clock or expired quiet confirmation fails closed for cover traffic.

An ISC1 frame is exactly 2,048 bytes: magic at 0..4, authenticated seven-day
expiration at 4..12, a random 32-byte nonce at 12..44, and random padding. Every
updated frame uses the same 288-byte authenticated trailer at 1760..2048:
16-byte `ISYEET-COVER-V1\0` marker, one consent byte, an eight-byte signed
big-endian confirmed relay lease timestamp, one receipt-count byte, eight 32-byte nonce
slots, and six reserved bytes. Unused slots and reserved bytes remain random.
Count-selected receipt slots acknowledge covers from that specific email and
identity only. The 8,192-byte envelope and relay `SendRequest` are unchanged.

Cover frames use the existing official Signal session and ordinary durable
outbox, receive, duplicate and ACK paths. A validated cover returns `cover:true`
with no text, alert, history row, unread change or automatic response. A client
whose mode is now off still consumes in-flight covers silently. It retains the
last eight unexpired received nonces per peer and piggybacks receipts only when
it later sends a frame for another reason. Hosts must persist ratchet, receipt
and replay changes before acknowledging covers, exactly as for real messages.

There is at most one queued cover globally, eight unreceipted covers per peer,
64 traffic peers, and 4,096 cover creations in a rolling seven-day window.
Accepted, canceled and uncertain sends retain their nonce reservations until an
authenticated receipt or the original deadline; HTTP acceptance alone does not
free a slot. Receipts can remove a still-queued cover already received by the
peer. Mode disable, expired consent and identity warnings cancel queued covers.
Key replacement does not inherit consent, clear the creation budget, or let the
new key acknowledge old-key reservations. New advertisements may establish
consent for the new verified key while the old reservations keep their bounds.

The host chooses independent random 15–45-second foreground send slots, gives
pending real ciphertext priority, then may select a random eligible contact for
a cover. The core rechecks eligibility and limits when creating a cover. It
does not provide constant-rate or recipient-independent anonymity: activity
windows, recipient choice, outages, backlogs and outer expiration timestamps
still disclose characteristics. Cover traffic can pause at its limits or when
there is no fresh consenting contact; the host must describe that honestly.

The native client should PUT `/v1/contacts` with
`{"emails":[<verified canonical contact emails>]}` after persisting verification,
and resynchronize before send/retry/receive. Never publish an unverified contact.

## C JSON ABI

Header: `include/isyeet.h`. `isyeet_call(const char *)` accepts NUL-terminated
UTF-8 JSON (maximum 8 MiB), returns allocated NUL-terminated JSON. Release once
with `isyeet_free_string(char *)` (alias `isyeet_free`). No network or disk access
occurs inside this interface. Serialize all calls for an account.

Every success is `{"ok":true,"state":{...},"data":...,"resolved_message_ids":[]}`. Every failure is
`{"ok":false,"error":"generic safe text"}` and contains no proposed state.
The `state` object is opaque; it includes all keys, ratchets, identity pins,
verification decisions, recent local messages, outbox and replay tracking.
Atomically persist the returned state before adopting it, displaying newly
received plaintext, sending ciphertext, or ACKing any incoming message.

Before removing a contact, migrate any locally observed identity-change warning
through `block_groups_for_contact` on the same proposed state. This preserves the
distinction between a voluntary removal and a pin known to have changed. Clear
the caller's obsolete warning sidecar only with the successful removal save.

| Request fields (besides `op`) | `op` | `data` result |
| --- | --- | --- |
| `email` | `init` | Wire `KeyUpload` |
| `state` | `key_upload` | Current public `KeyUpload`; publish through initial PUT only while `initial_upload_pending` is true |
| `state`, `keys` (`KeyUpload` from authenticated `/v1/keys/me`) | `validate_registered_keys` | `null`; accepts only this device's current or exactly journaled pair and a known remaining EC subset, never adopts remote keys |
| `state` | `confirm_initial_upload` | Snapshot; clear fresh-initial-upload flag after confirmed initial PUT or validated own registration |
| `state`, `inventory` (`{generation,keys}` from GET `/v1/keys/maintenance`) | `prepare_key_maintenance` | Public maintenance request or `null`; save returned state before any PUT |
| `state`, `receipt` (`{operation_id,generation}` from PUT `/v1/keys/maintenance`) | `confirm_key_maintenance` | Snapshot after exact pending UUID and next-generation validation |
| `state`, `bundle` (wire `KeyBundle`) | `add_contact` | `{email,fingerprint,verified}` |
| `state`, `email`, `fingerprint` (full 64 hex) | `verify_contact` | `{email,fingerprint,verified:true}` |
| `state`, `email`, `bundle`, `previous_fingerprint`, `fingerprint` (both full 64 hex) | `replace_contact` | Legacy ABI compatibility only, not the current app/CLI workflow; returns `{email,fingerprint,verified:true}` after the same retired-pin protection and fresh signed-bundle validation |
| `state`, `email`, `previous_fingerprint` (current full 64 hex) | `remove_contact` | `{email,removed:true}`; atomic local removal and targeted cancellation, followed by caller permission sync |
| `state`, `recipient`, `text` | `encrypt` | Wire `SendRequest`, already appended to state outbox |
| `state`, `enabled` (boolean) | `set_traffic_mode` | Snapshot after changing cover mode; emits no messages |
| `state`, `server_time` (integer), `elapsed_seconds` (integer 0..60) | `confirm_traffic_quiet` | Snapshot after recording a fresh confirmed quiet-policy response; requires local Cover mode and fails with `cover_clock_unavailable` on invalid clock/round-trip bounds |
| `state`, `recipient` | `create_cover` | Ordinary wire `SendRequest` in outbox, without a history row; `cover_unavailable` on ineligibility or exhausted bounds |
| `state`, `title`, `members` (canonical peer emails, excluding self) | `create_group` | Immutable `Group`; automatically includes self |
| `state`, `group_id`, `text` | `encrypt_group` | `[SendRequest]`; all legs and one logical history row committed together |
| `state`, `email`, optional `fingerprint` (expected old pin) | `block_groups_for_contact` | `null`; permanently warns the pin, blocks affected groups and cancels every unsent leg; expected-pin mismatch is a no-op |
| `state`, `message` (wire `QueuedMessage`) | `decrypt` | `LocalMessage` described below |
| `state`, `id` | `sent` | `null`; removes matching accepted message from outbox |
| `state` | `snapshot` | Snapshot described below, with proposed state after expiry/resolution |
| `state` | `expire` | Same snapshot, with expired content removed from the returned state |
| `state` | `history` | Retained `LocalMessage` array after expiry |

Snapshot `key_maintenance` is `{initial_upload_pending:bool,pending:request|null,
next_check_at:UTCseconds}`. Zero means a check is due; a pending request always
takes priority. The request is `{operation_id,expected_generation,keys}`, where
`keys.pre_keys` contains additions only. Other key fields hold the unchanged
identity/registration and current or replacement signed pair. The receipt is
`{operation_id,generation}` with the expected generation plus one. Maintenance
errors use the safe code `key_maintenance_rejected` and never return a state.

`contacts` contains `{email,fingerprint,verified}` records. A `LocalMessage` is
`{id,sender,recipient,duplicate,expires_at,expired,deferred,cover,text?,security_alert?}`;
optional values are omitted. `SendRequest` includes the absolute `expires_at`
deadline alongside `id`, `recipient`, and `envelope`. Missing legacy deadlines
decode as zero for migration; new relay requests must carry a valid deadline. `messages` includes outgoing and incoming records. SHA-256 fingerprints
cover the full serialized public identity key (not the Gmail address or server
response). Contacts are pinned, cannot silently change, and must be manually
verified before encrypt/decrypt. `replace_contact` requires an existing contact,
an exact canonical target/bundle email, the current pin and a different new
identity matching the independently supplied fingerprint. It validates fresh
Signal signed prekeys on a clone, then atomically replaces that peer's session,
pin and verification while removing its old direct history/outbox, retaining group
history and blocking affected groups with every pending group leg cancelled. Failure leaves the
original state intact and returns
`Contact replacement rejected; existing contact remains unchanged.`

Snapshot adds `groups`, `outbox_refs`, `pending_group_senders`, `next_expiry`, and
`resolved_message_ids`. Its `traffic` object is
`{enabled,eligible_contacts,remaining_budget,cover_outbox_ids,outstanding}`.
`remaining_budget` is 0..4096; `outstanding` is 0..512 and includes accepted and
canceled reservations. `cover_outbox_ids` has at most one local transport ID;
exclude it from message counts and metadata UI. These identifiers never become
extra wire fields. Eligibility also accounts for the one-queued-cover and total
outbox bounds, so it can be empty while a saved cover is waiting for a slot.
The native API is `cover_enabled()`, `set_traffic_mode(bool)`,
`confirm_traffic_quiet(server_time, elapsed_seconds)`, `create_cover(&str).await`,
`cover_candidates()` and `cover_message_ids()`.
Create and mode changes return proposed state under the same persistence rule.

A `Group` contains `{id,title,members,blocked,created_at,nonce}`;
members are `{email,fingerprint}` and `id` is a 64-hex descriptor hash. The local
`created_at` and descriptor `nonce` are implementation fields; UI needs only the
first four fields. `outbox_refs` is a separate array of
`{id,group_id,message_id,recipient}` linking transport IDs to local history IDs;
never add these fields to serialized relay `SendRequest` bodies.

New message metadata fields are optional: `group_id`, `logical_id`, `sent_at`,
`received_at`, `sender_fingerprint`, `status`, `accepted_count`, `recipient_count`.
Old records keep missing metadata unavailable. Sent time is derived from the
authenticated expiry; receipt time is local. Fingerprints capture the identity
when the message was authenticated or created and do not change later. Generic
rejections have no invented authenticated metadata. Status is `queued`,
`partially_accepted`, `relay_accepted`, `received`, or `cancelled`; counts describe
relay acceptance only and are omitted for incoming messages. Group rows use a
deterministic UUID bound to group, canonical author email, author fingerprint and
authenticated logical UUID. `logical_id` preserves that authenticated UUID;
`recipient` on a group row is the local canonical account email.

`deferred:true` is an authenticated quarantine transition with no displayed text
or history row; persist and ACK it normally. `pending_group_senders` contains
only already-verified sender emails for a generic banner. `next_expiry` covers
hidden quarantined plaintext as well as history, outbox, cover consent and
bounded receipt/reservation deadlines. The
top-level `resolved_message_ids` lists newly promoted history IDs during exactly
that ABI call; the same IDs appear in snapshot/expire data. Accumulate these IDs
across follow-up calls and save unread bookkeeping atomically with the state.
They are not serialized inside opaque state and must not make old history unread.

Migrate every existing external identity-warning sidecar through
`block_groups_for_contact` before normal maintenance. That operation applies its
pin warning before pruning and deliberately suppresses quarantine resolution for
the entire call, allowing all warnings to be installed first. A failed-save
warning may include its captured expected fingerprint, so recovery cannot warn a
different replacement key that was already durably saved.

Passing the local account email as `encrypt.recipient` uses the self channel;
`decrypt` accepts that same canonical sender only with the pinned local identity.
There is no separate self-contact, key claim, verification operation or recipient
permission entry. The optional opaque `self_channel` state is initialized on
first send and defaults to absent in existing state. No self `LocalMessage` is
created by encryption; successful decryption creates the single received record.
Callers must route self ciphertext through the relay rather than invoking decrypt
as a local echo. Both self stores must be persisted together with the normal
outbox/dedupe state before send and ACK.

`contact_verification_required` and `contact_identity_changed` are stable
failure strings: do not ACK either message. The latter is specifically a Signal
untrusted-identity error; it rolls back Signal mutations and creates no history
or dedupe record, allowing the same queued ciphertext after verified replacement.
Native callers must durably record the affected known contact in bounded local
metadata alongside the opaque state, then block composing and retrying that peer
until a successful replacement and metadata clearing are atomically saved.
Do not change its pinned identity automatically. A malformed or unauthenticated message
from a verified contact returns a successful state transition with a generic
`security_alert` and no text; persist and ACK it. Authenticated invalid plaintext
advances the ratchet and records rejection. Unauthenticated ciphertext never
commits intermediate Signal store mutations. Duplicate messages return
`duplicate:true` without repeating plaintext and can be ACKed after persistence.
An authenticated expired message returns `expired:true`, no text and no alert;
its ratchet and content-free dedupe transition must be persisted before ACK.
It is never added to history or unread state. Dedupe metadata lasts up to one
week after first receipt (or once after migration for legacy IDs), never renewed
by a duplicate; this supports ACK retries after the message itself expires.

Call `expire` and atomically save its returned state before loading or publishing
a snapshot, on resume, at expiration deadlines, and before each network retry.
All ABI operations prune their returned state; do not discard the state returned
by `snapshot` or `history`. The native Rust read-only `snapshot()`/`history()`
methods filter expired content on clones without promoting quarantine; callers
must run and persist `expire()` to remove expired disk content or promote eligible
group text. Production time comes only from the system clock, with a
persisted nondecreasing observation to prevent a clock rollback reviving history.

Limits: 64 contacts, 32 groups, 64 quarantined group bodies, 16 pending outgoing
envelopes, most recent 200 local messages, 4,096 transport duplicate IDs,
4,096 logical group dedupe records, and 8,192 last-resort Kyber replay markers. Older
transport IDs are pruned; Signal's ratchet also rejects replayed ciphertext.
Automatic prekey maintenance is bounded as described above; private identity
recovery still requires an explicit new registration and contact verification.
Empty group records retire after one week only when no retained message, pending
leg or quarantine references them. A blocked record remains while all captured
pins still match the locally verified identities, preventing silent revival;
after a real pin replacement, an empty expired blocked record may retire.
