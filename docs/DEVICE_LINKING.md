# Secure device linking

Status: experimental device authorization implemented and tested locally, disabled
in ordinary builds. This is not yet multi-device messaging and is not deployed to staging or
production. The deployed passkey baseline still supports one messaging device.

## User experience and trust

An account starts in the iPhone app. The primary phone keeps the account's
existing Signal identity key as its authorization root. A companion generates
its own Signal identity key locally; neither its private keys nor the phone's private
keys travel through the relay. A passkey signs in to the account, but cannot by
itself approve a messaging device.

The first implementation uses bounded, printable ASCII copy-and-paste codes.
There is no camera permission, pairing web page, link broker or secret in a URL.
The phone and companion display the exact account, service origin, device label
and public-key comparison information. Approve only a request initiated on the
companion in front of you, after comparing the information on both devices.
A signed code received from someone else does not establish whose device it is.

1. The phone initializes an authorization record rooted in its current identity.
2. The experimental CLI signs in through the existing passkey browser flow and
   reads the signed list. It verifies the exact account/service and the primary
   fingerprint entered from the phone. The temporary account token is discarded;
   it is not saved in the companion state. The companion then creates a separate
   pending installation and a signed request containing its new public key,
   registration ID and a fresh random nonce. The primary assigns an unused device
   ID when approving it. The request expires after five minutes.
3. After inspection and explicit approval, the phone's Rust core signs the
   companion certificate and updated device list. The phone saves the exact
   proposal before requesting a fresh user-verified passkey assertion for the
   `device_manage` purpose. Canceling the passkey prompt retains that proposal
   for safe retry; it does not free its allocated version or device ID.
4. The relay verifies both devices' signatures, the fresh passkey grant and the
   expected previous device-list version/hash, then commits the update atomically.
5. The phone returns a signed approval code. The companion checks it against its
   original pending request and private key before accepting it.

The result of this increment is **Device approved; messaging unavailable**.
It grants no device session, prekey upload, inbox, message history or permission
to call the existing messaging API. The initial limit is the primary phone and
one companion. A companion cannot authorize another device or replace the root.
The CLI
`device-status` command reports saved local authorization only; it does not check
live revocation. Exporting an approval code requires a verified observation of
the current signed list within the last 60 seconds. See the [experimental CLI reference](../crates/client/README.md).

Passkeys remain in a separate Settings section from Messaging Devices. Removing
a passkey and revoking a messaging device are different actions. A synced passkey
may work on several devices; that does not copy or authorize Signal keys.

## Cryptographic boundary

All Signal key generation and signatures use the existing pinned official
libsignal revision. The Worker uses that revision's small `libsignal-core`
verifier compiled to WebAssembly. It does not implement a signature primitive.
The shared `crates/wire/src/linking.rs` defines the versioned, domain-separated
binary transcripts; JSON is transport, not the signed canonical representation.

A certificate binds the account UUID, root epoch, device ID, identity key,
registration ID, printable label and exact link-request hash. The signed device
list also binds the service origin, root key, version, predecessor hash, issue
and expiry times, highest issued device ID, and ordered certificates. The root
signs the complete change intent as well. The companion proves possession by
signing its request. Verifiers reject unknown fields, oversized data, ambiguous
encodings, noncanonical keys, invalid signatures and mismatched contexts.

The root fingerprint remains the account's existing pinned Signal fingerprint.
This experiment does not silently trust a new root or modify contacts' pins.
Approval of a companion is subordinate to that root. A compromised primary key
can authorize another device; the signatures do not repair primary compromise.

## Persistence, freshness and revocation

Device IDs are 1–127: primary 1, companions 2–127. IDs are never reused within a
root epoch. The core returns each signed proposal with the complete next state. The primary
app atomically saves that state, including its allocated version and device-ID
high-water marks, before exposing or transmitting the proposal. Canceled or expired proposals
burn their allocations. Subsequent updates may skip values, but must strictly
advance and name the exact committed predecessor hash. This avoids signing two
different proposals with the same allocated version after an interrupted flow.

Clients save and retry the exact signed intent. The server retains bounded exact
retry receipts for 24 hours, tied to the account, original intent and action
proof. A receipt confirms the historical operation; clients still need the
current signed list before future messaging. The experimental limits are 16 ordinary retained changes per account per 24 hours
plus one reserved companion-removal receipt, and 100,000 receipts globally, with
10 management requests per account per minute. The reserved removal slot prevents
ordinary renewals from exhausting an account's ability to revoke its one active
companion; global hard capacity or service unavailability can still block writes.
Used candidate request IDs, hashes and identity keys remain reserved within the
root epoch, so revocation cannot be followed by replaying the same candidate.
All authority changes and receipt writes are transactional. Account deletion and re-enrollment remove experimental
metadata through database foreign-key cascades, including when the ordinary
build is subsequently run.

A device list is a lease lasting at most 24 hours. Future device messaging must
require a valid signed lease and reject rollback against locally pinned versions.
The primary must be available to renew the lease. An honest relay can enforce
revocation immediately; a malicious relay could suppress a newer revocation
until a previously signed lease expires, subject to bounded clock skew. This is
not key transparency or a guarantee against server equivocation. A complete local
state rollback is also outside the protection of an on-device high-water mark;
restoring old authorization state must not resume signing as if it were current.

The primary can revoke a companion with another explicitly approved, freshly
passkey-authenticated update. Revocation cannot retract plaintext already read or
ciphertext already delivered. Losing the primary requires account re-enrollment
and fresh contact verification; a companion has no recovery authority. Re-enroll
changes the root and must trigger the existing prominent identity-change warning.

## Work required before enabling messages

The authorization experiment intentionally leaves the existing v2 ratchets and
single-device queues untouched. Enabling linked messaging needs a separately
versioned protocol and persisted client-state migration:

- Address every Signal session, identity and prekey by account plus device ID.
  The present core uses a single identity and device ID 1; copying that state
  into another installation would duplicate ratchets and is unsafe.
- Authenticate each companion through its certified key and issue narrowly
  scoped, revocable device sessions. An account login alone must not unlock
  message routes.
- Maintain distinct device prekey inventories, inboxes and acknowledgments.
  Removal must invalidate sessions and pending delivery atomically.
- Verify the current root-signed device list before creating every outgoing
  batch, then encrypt independently to each authorized recipient device and
  other authorized sender devices. Persist the batch before sending; retries
  keep the original ciphertext, recipients and expiry.
- Bind encrypted sender/recipient device identities and account context so
  cross-device forwarding cannot masquerade as an original sender. Group,
  self-message, duplicate and partial-delivery behavior need explicit tests.
- Keep the fixed-size envelopes, seven-day maximum retention, printable ASCII
  rejection and notification/cover-mode policy. Device fanout increases traffic
  and reveals device-count information to the relay; do not claim otherwise.
- Test offline devices, queued messages during revocation, stale or forked device
  lists, expired leases, crashes at each persistence boundary, re-enrollment,
  account deletion and real phone/desktop interoperability before release.

No old history transfers in the first linked-messaging release. A new companion
should receive only messages sent after authorization. History transfer would
require a separate, explicitly approved design and is outside this scope.

The session-management model is informed by Signal's
[Sesame specification](https://signal.org/docs/specifications/sesame/).
Signal's [linked-device provisioning description](https://signal.org/blog/a-synchronized-start-for-linked-devices/)
has different key-transfer details. This is ISYEET device authorization using
official libsignal, not a claim to implement Signal's full provisioning protocol.
The ISYEET authorization protocol requires independent review before production.
