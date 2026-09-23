# Matching dependency sources

Extract this archive into the corresponding ISYEET client source export. It
adds `vendor/`, portable `.cargo/config.toml`, upstream license supplements and
these manifests. Then run `cargo build --offline --locked -p isyeet-client`.
Install the Rust toolchain and system build tools (including protoc) separately;
this archive does not redistribute Rust, Xcode, Apple SDKs or system libraries.
No dependency version, Git revision, Cargo.lock or exported source is changed.

DEPENDENCY_RELEASE.json binds this package to the original RELEASE.json and
Cargo.lock hashes. DEPENDENCY_LICENSES.json records Cargo's declared license,
original source, included notice files and the hash of each vendor checksum map.
Vendored upstream files and their checksum maps are preserved unchanged. Root
notices omitted from Git subcrates are copied separately from their pinned Git
commits. Reviewed registry notice supplements record their immutable revision,
source URL and content hash. The package-declared MPL-2.0 text is supplied from
Mozilla where the pinned HPKE upstream omits it; root Apache/MIT notices do not
relicense HPKE. Winapi target import-library notices come from their exact locked
parent package; their own package does not record an immutable source revision.
Entries with no included notice file are explicitly listed; declaring
a license in Cargo metadata is not a substitute for reviewing applicable
redistribution obligations. This manifest is an inventory, not legal advice.

Cargo metadata was resolved offline with --locked. A successful metadata check
is not a complete build or security audit. Upstream test fixtures remain part of
their exact source packages; no ISYEET account state, signing key or credentials
are included. The external archive sidecar records the final compressed hash.
