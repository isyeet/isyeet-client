# Third-party software

The iOS executable statically links the shared ISYEET Rust client core and official Signal `libsignal-protocol`, pinned in the sibling backend repository to upstream v0.103.0, commit `ba133bd3457f556fbf56db0a5ab985de0af79da6`.

Signal libsignal is licensed AGPL-3.0-only. ISYEET source is also AGPL-3.0-only; consult `LICENSE` and preserve the corresponding source and dependency notices when distributing a binary. Transitive Rust dependency licenses and their exact locked versions are recorded by the backend Cargo dependency graph. See the backend's `THIRD_PARTY_NOTICES.md` for dependency-audit details. Swift uses system Apple frameworks and has no third-party Swift dependencies.
