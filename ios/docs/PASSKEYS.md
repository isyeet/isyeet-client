# Native passkey enrollment (protocol v2)

This is a clean break from email accounts. An account has an immutable random
UUIDv4 and a chosen 3–24 character lowercase ASCII username, starting with a letter
and otherwise using letters, digits and underscore. Username lookup does not claim
a prekey. Signal sessions, pins, group membership and routing use the account UUID.

`AuthenticationServices` handles both passkey registration and authentication.
No passkey private key enters ISYEET. The app requires user verification and
resident credentials, uses only ES256 for registration, forwards the standard
WebAuthn response to the server, and never parses signatures itself. A system
passkey/password manager or an independent hardware security key can register an
additional credential. Removal authenticates with a different surviving credential;
the server enforces this independently and revokes all sessions after removal.

Settings → Passkeys lists credentials, accepts a printable ASCII label, and supports
adding/removing up to eight credentials. Removing a synced credential invalidates
all its copies. There is no email recovery or support bypass. Users should register
an independent backup credential before losing their primary credential.

Passkeys do not copy Signal keys. This release still supports one active messaging
device. Signing in on another installation cannot silently replace the active keys;
the user must explicitly re-enroll, which revokes old sessions and requires contacts
to remove the old pin and independently verify the new fingerprint. Desktop device
linking is not implemented in this release.

The staging RP ID is `api-staging.isyeet.io`; production is `api.isyeet.io`. Each
configuration has only its own `webcredentials:` associated domain. These API hosts
must serve `/.well-known/apple-app-site-association` with a `webcredentials.apps`
entry of `KBRQXAWK93.com.isyeet.app`, without redirects. The Apple app identifier and
provisioning profile must enable Associated Domains before a signed device build can
use the native system flow. The marketing domain is not an authentication origin.

Version 1 Keychain accounts and operation journals produce an explicit incompatibility
screen. Clearing them requires the user's destructive confirmation; neither the old
private keys nor old email contacts are renamed into version 2 identities. Local
storage schema 2 requires a matching username and account UUID; core state schema 7
has its own validation.

Deletion and replacement retain the existing durable operation journal. A narrow
purpose-bound action token is saved in the ThisDeviceOnly Keychain before a destructive
request. An uncertain reply is retried with the same operation, keys and proof before
requesting fresh authentication. Only a server receipt or authoritative reconciliation
confirms completion. After the fixed operation deadline, the user may explicitly clear
local data without claiming that a server operation completed. Re-enrollment needs a
fresh login and an exact comparison of the prepared keys with the current server keys
before activating the new identity.

## Validation (2026-10-05)

The v7 Rust XCFramework was rebuilt for physical arm64 iOS and arm64 iOS Simulator.
The native changes passed 53 domain tests, 59 AppModel lifecycle scenarios, and the
release configuration guards. Staging and production Simulator builds and a production
unsigned physical-device build passed with Swift 6 strict concurrency checking.

The exact passkey-only source snapshot was also built independently in a disposable
directory, excluding the unrelated Manifesto files and project/UI references. It used
the rebuilt XCFramework, no local configuration override, a fresh derived-data directory,
the `ISYEET` scheme, `Debug` configuration, and the generic iOS Simulator destination
with `CODE_SIGNING_ALLOWED=NO`. This arm64 staging build passed against the iOS 27 SDK.
Its generated configuration contains `https://api-staging.isyeet.io` and the matching
`api-staging.isyeet.io` relying party. The sole build warning was the expected skipped
App Intents metadata extraction because the app does not use App Intents.

After the final lockfile update to `yoke-derive` 0.8.4, both native core slices were
rebuilt with `--locked`. The committed passkey-only snapshot then passed fresh unsigned
staging Simulator and production iPhone builds using those libraries. The snapshot
excluded the unrelated Manifesto work and local configuration overrides; the only
additional source edits renamed obsolete OAuth references in comments and test output.

These checks do not validate provisioning, Associated Domains delivery, a live native
passkey ceremony, or hardware-key behavior. No signed archive or TestFlight upload was
performed for this passkey change.

Validation does not replace real hardware acceptance. Test registration, cancellation,
a second password manager/security key, removal with a different credential, lost-reply
recovery, and production/staging isolation on a provisioned device after API deployment.

## Device authorization experiment

The native authorization preview is compiled behind both `DEBUG` and the explicit
`ISYEET_DEVICE_AUTHORIZATION_EXPERIMENT` flag. Ordinary Debug, Release, production,
and TestFlight builds cannot use it; the native API adapter also restricts these
calls to the staging origin. No shared scheme enables the flag.
The bundled Rust core independently requires its nondefault `device-linking` feature;
`scripts/build-core.sh` deliberately builds without it. Use a separate temporary
Simulator framework when testing the preview, leaving the ordinary framework intact.

In that preview, Settings → Messaging Devices manages an independent signed device
list. The manual request field accepts at most 16,384 ASCII bytes in the versioned
public-code format. The Rust core verifies the request and returns its exact account,
label, key fingerprint, request fingerprint, and expiry. The approval screen shows
both complete fingerprints alongside the current account and service origin; the
user must compare them with the requesting device before approving.

The primary saves the exact signed proposal and burned allocation counters before
requesting a fresh `device_manage` passkey proof or sending the change. The UI exposes
an approval response only after durable confirmation and a newly fetched, verified
current roster. Refresh reconciles a lost reply; an expired unpublished proposal is
cleared only after the core verifies its unchanged predecessor. The limit is two
authorized devices and a 24-hour roster lease. The requesting device receives neither
private messaging keys nor old message history.

This increment is labeled **Device approved; messaging not yet enabled**. It does not
issue a companion messaging session, perform per-device fanout, or change any v2
message route. Do not enable it for testers as though it were linked messaging.

Focused checks are `swift test`, `scripts/test-lifecycle.sh` (including direct calls
with the feature disabled), and `scripts/test-lifecycle.sh --device-authorization`
(synthetic persistence failure, lost-reply/relaunch, expiry and exact retry scenarios).
The synthetic harness tests native save/network ordering; real cryptographic and
rollback checks belong to the Rust core and real FFI integration tests.

On 2026-10-05, validation passed 58 domain tests, 60 ordinary lifecycle scenarios,
and four enabled-authorization lifecycle scenarios. The real C ABI test in
`scripts/test-device-authority-ffi.py` passed bootstrap, separate companion key
generation, fingerprint/request binding, malformed request and clock rejection,
saved-proposal round trips, lost-reply reconciliation, receipt-only approval withholding, companion acceptance,
rollback/origin rejection, primary-revocation rejection, companion revocation,
and revoked-request replay rejection. Its header documents a repeatable invocation.

The filtered source snapshot, excluding unrelated Manifesto work, passed an ordinary
staging Simulator build and unsigned production iPhone build using the default core.
It also passed an explicitly enabled staging Simulator build using a separately
packaged experimental core. Only the expected unused App Intents metadata warning
was emitted. These were compile/link checks, not live passkey approvals; no device
authorization feature was signed, uploaded, or enabled for TestFlight.
After the final core confirmation change, the opt-in Simulator build and real C ABI
regression passed again. The latter explicitly checks that a valid receipt cannot
release an approval code until a matching current roster is observed.
