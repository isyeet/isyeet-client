# ISYEET clients

I Send You E2E Text: an iPhone app and local command-line client for end-to-end
encrypted printable ASCII messages. This repository contains corresponding
source for the distributed clients, licensed AGPL-3.0-only. Signal's official
libsignal is pinned; its implementation has not been replaced. Source licenses
do not grant ownership of the ISYEET name or promise access to the hosted relay.

**Development source candidate; independent security review is still pending.**
Publishing this source does not upload an iOS binary or announce general
availability. Experimental device authorization is disabled by default and does
not provide companion messaging. The native app includes an offline Manifesto
reader. See [device authorization and remaining work](docs/DEVICE_LINKING.md).

Access to
https://api.isyeet.io is initially limited to invited testers. Staging accounts
are separate. The clients enforce independent key verification, seven-day
message expiry and fixed-size envelopes; these do not provide anonymity or a
guarantee that all copies disappear. Cover traffic runs only while active.

## Build the Rust client

Install Rust 1.94.0 or newer and Protocol Buffers `protoc` (also Clang/CMake where
required by the pinned dependencies). From this directory:

```sh
cargo build --locked --release -p isyeet-client
cargo test --locked -p isyeet-client
```

See [CLI and core API](crates/client/README.md). Use a separate private state file
for each environment. Protocol v2 uses usernames and passkeys; private message
keys, bearer credentials and account-state files must stay private. Passkey sign-in
does not link a second messaging installation. Experimental device authorization
is available only with an explicit nondefault build feature; it grants no second
inbox or messaging session. Ordinary builds and TestFlight keep it disabled.

## Build for iPhone

On macOS with Xcode and the iOS SDK installed:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
ISYEET_BACKEND_PATH="$PWD" bash ios/scripts/build-core.sh
```

Open `ios/ISYEET.xcodeproj` and select Debug/Release for staging or Production
for the production origin. Debug/Release accept your signing team in the ignored
`ios/Config/Local.xcconfig`; Production deliberately excludes local overrides.
For a Production build, configure your own team in Xcode's signing settings or
pass `DEVELOPMENT_TEAM=YOUR_TEAM` to `xcodebuild`. Configure Associated Domains
and your service's apple-app-site-association file for your app identifier. See
[iOS passkey setup](ios/docs/PASSKEYS.md). Building the source does not require
the operator's Apple or Cloudflare secrets. App Store/TestFlight export
requires your own Apple account and distribution configuration. The included
`testflight.sh` is the operator's guarded release wrapper and pins its team;
adapt those checks and export options for your own account, or export in Xcode.
The release's build number is in `RELEASE.json`; pass it as
`CURRENT_PROJECT_VERSION` when archiving (the project default is a development
placeholder). Production release archives use the Production configuration.

Run `swift test --package-path ios` and `bash ios/scripts/test-lifecycle.sh` for
the domain and actual application-model checks. The release script is scoped to
internal testing, never automatic public App Store distribution.

## Source and dependencies

`RELEASE.json` identifies the original source revisions and hashes every exported
file. The release dependency-source archive includes pinned third-party source
and its upstream licenses, plus Cargo's offline vendor configuration. Individual
components retain their notices. See `THIRD_PARTY_NOTICES.md` and `LICENSE`.
Use the matching source tag/archive for the installed build; newer source may
have a different state format. Never roll back a saved cryptographic state.

Support and privacy requests: support@isyeet.io.
[Privacy](https://www.isyeet.io/privacy/) · [Terms](https://www.isyeet.io/terms/) ·
[Support](https://www.isyeet.io/support/).
