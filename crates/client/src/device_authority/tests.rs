use super::*;

const ORIGIN: &str = "https://api.isyeet.io";
async fn primary() -> State {
    State::initialize("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "alice")
        .await
        .unwrap()
}
fn change(data: &Value) -> SignedDeviceChange {
    serde_json::from_value(data["change"].clone()).unwrap()
}
fn remote(state: &State) -> Option<SignedDeviceRoster> {
    state.device_authority.as_ref().unwrap().current.clone()
}
fn receipt(proposal: &SignedDeviceChange) -> DeviceAuthorityReceipt {
    DeviceAuthorityReceipt {
        operation_id: proposal.change.operation_id.clone(),
        roster_version: proposal.change.roster.roster.version,
        roster_hash: proposal.change.roster.roster.digest().unwrap(),
        messaging_available: false,
    }
}
async fn initialize() -> State {
    let mut state = primary().await;
    let now = current_time().unwrap();
    state.device_authority_observe(ORIGIN, None, now).unwrap();
    let proposal = change(&state.device_authority_prepare(ORIGIN, now).await.unwrap());
    state.device_authority_commit(receipt(&proposal)).unwrap();
    state
        .device_authority_observe(ORIGIN, remote(&state), now)
        .unwrap();
    state
}
fn candidate(state: &State) -> DeviceCandidate {
    DeviceCandidate::create(
        remote(state).unwrap(),
        "Test desktop",
        &fingerprint(&state.upload.identity_key).unwrap(),
        current_time().unwrap(),
    )
    .unwrap()
}
fn candidate_at(state: &State, now: i64) -> DeviceCandidate {
    // Explicit virtual clock fixture; production constructors reject such jumps.
    let initial_roster = remote(state).unwrap();
    let roster = &initial_roster.roster;
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let pair = IdentityKeyPair::generate(&mut rng);
    let mut nonce = [0; 32];
    rng.fill_bytes(&mut nonce);
    let request = DeviceLinkRequest {
        origin: roster.origin.clone(),
        account_id: roster.account_id.clone(),
        root_epoch: roster.root_epoch.clone(),
        root_identity_key: roster.root_identity_key.clone(),
        request_id: uuid::Uuid::new_v4().to_string(),
        identity_key: encode(pair.identity_key().serialize()),
        registration_id: 500,
        label: "Clock fixture".into(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        issued_at: now,
        expires_at: now + DEVICE_LINK_LIFETIME,
    };
    let request = SignedDeviceLinkRequest {
        signature: sign(&pair, &request.signing_bytes().unwrap()).unwrap(),
        request,
    };
    DeviceCandidate {
        version: 1,
        identity_pair: encode(pair.serialize()),
        initial_roster,
        request,
        approved: None,
    }
}

#[test]
fn primary_and_companion_roundtrip_never_exports_root_or_enables_messages() {
    futures::executor::block_on(async {
        let mut state = initialize().await;
        let before = state.key_upload();
        let identity = state.identities.pair.clone();
        let mut candidate = candidate(&state);
        let now = current_time().unwrap();
        let code = candidate.code().unwrap();
        let inspected = state.device_authority_inspect(&code, now).unwrap();
        let proposed = state
            .device_authority_approve(&code, inspected["request_hash"].as_str().unwrap(), now)
            .await
            .unwrap();
        assert!(proposed["approval_code"].is_null());
        assert_eq!(proposed["messaging_available"], false);
        let proposal = change(&proposed);
        verify_device_change(&proposal).unwrap();
        assert_eq!(
            proposal.change.roster.roster.devices[1]
                .certificate
                .device_id,
            2
        );
        let signature = proposal.signature.clone();
        state = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(
            change(&state.device_authority_prepare(ORIGIN, now).await.unwrap()).signature,
            signature
        );
        // Lost reply: only observing the exact published signed roster releases approval.
        let confirmed = state
            .device_authority_observe(ORIGIN, Some(proposal.change.roster), now)
            .unwrap();
        let approval = confirmed["approval_code"].as_str().unwrap();
        assert!(!approval.contains(&identity));
        let clear = URL_SAFE_NO_PAD
            .decode(approval.strip_prefix(APPROVAL_PREFIX).unwrap())
            .unwrap();
        assert!(!String::from_utf8(clear).unwrap().contains("identity_pair"));
        let status = candidate.accept(approval, now).unwrap();
        assert_eq!(status["approved"], true);
        assert_eq!(status["messaging_available"], false);
        assert_eq!(state.key_upload(), before);
        assert_eq!(state.identities.pair, identity);
        assert!(state.sessions.0.is_empty());
        assert!(
            serde_json::from_value::<State>(serde_json::to_value(&candidate).unwrap()).is_err()
        );
    });
}
#[test]
fn receipt_only_commit_does_not_release_approval_before_current_roster_observation() {
    futures::executor::block_on(async {
        let mut state = initialize().await;
        let c = candidate(&state);
        let now = current_time().unwrap();
        let proposal = change(
            &state
                .device_authority_approve(
                    &c.code().unwrap(),
                    &c.request.request.digest().unwrap(),
                    now,
                )
                .await
                .unwrap(),
        );
        let committed = state.device_authority_commit(receipt(&proposal)).unwrap();
        assert!(committed["approval_code"].is_null());
        state = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(state.device_authority_snapshot().unwrap()["approval_code"].is_null());
        let observed = state
            .device_authority_observe(ORIGIN, Some(proposal.change.roster), now)
            .unwrap();
        assert!(observed["approval_code"].is_string());
        let sidecar = state.device_authority.as_ref().unwrap();
        assert!(sidecar.data(now + DEVICE_TIME_SKEW + 1).unwrap()["approval_code"].is_null());
        let mut wrong_observation = sidecar.clone();
        wrong_observation.observed_hash = ZERO_HASH.into();
        assert!(wrong_observation.data(now).unwrap()["approval_code"].is_null());
    });
}
#[test]
fn root_signatures_do_not_make_noncanonical_companion_keys_valid() {
    futures::executor::block_on(async {
        let mut state = initialize().await;
        let c = candidate(&state);
        let now = current_time().unwrap();
        let data = state
            .device_authority_approve(
                &c.code().unwrap(),
                &c.request.request.digest().unwrap(),
                now,
            )
            .await
            .unwrap();
        let mut signed = change(&data).change.roster;
        let root = state.identities.get_identity_key_pair().await.unwrap();
        signed.roster.devices[1].certificate.identity_key =
            encode([&[5][..], &[0; 32][..]].concat());
        signed.roster.devices[1].signature = sign(
            &root,
            &signed.roster.devices[1]
                .certificate
                .signing_bytes()
                .unwrap(),
        )
        .unwrap();
        signed.signature = sign(&root, &signed.roster.signing_bytes().unwrap()).unwrap();
        assert!(verify_device_roster(&signed).is_err());
        let mut malformed = remote(&initialize().await).unwrap();
        malformed.roster.root_identity_key = encode([&[5][..], &[3; 33][..]].concat());
        assert!(verify_device_roster(&malformed).is_err());
    });
}
#[test]
fn changed_scope_transcripts_and_candidate_private_keys_are_rejected() {
    futures::executor::block_on(async {
        let mut state = initialize().await;
        let c = candidate(&state);
        let now = current_time().unwrap();
        let mut forged = c.clone();
        forged.request.request.label = "Other desktop".into();
        assert!(forged.code().is_err());
        let mut wrong_private = c.clone();
        wrong_private.identity_pair = candidate(&state).identity_pair;
        assert!(wrong_private.status().is_err());
        let request = c.code().unwrap();
        let request_hash = c.request.request.digest().unwrap();
        assert!(
            state
                .device_authority_approve(&request, ZERO_HASH, now)
                .await
                .is_err()
        );
        let proposal = change(
            &state
                .device_authority_approve(&request, &request_hash, now)
                .await
                .unwrap(),
        );
        let mut changed = proposal.clone();
        changed.change.operation_id = uuid::Uuid::new_v4().to_string();
        assert!(verify_device_change(&changed).is_err());
        let mut changed = proposal.clone();
        changed.change.roster.roster.origin = "https://other.isyeet.io".into();
        assert!(verify_device_change(&changed).is_err());
        let mut changed = proposal;
        changed.change.roster.roster.devices[1]
            .certificate
            .registration_id += 1;
        assert!(verify_device_change(&changed).is_err());
        for code in [
            format!("{request}="),
            format!(" {request}"),
            format!("{request}\n"),
            "x".repeat(MAX_DEVICE_CODE_BYTES + 1),
        ] {
            assert!(state.device_authority_inspect(&code, now).is_err());
        }
    });
}
#[test]
fn burned_bootstrap_versions_and_companion_ids_survive_expiry_and_restart() {
    futures::executor::block_on(async {
        let mut state = primary().await;
        let now = current_time().unwrap();
        state
            .device_authority_observe_at(ORIGIN, None, now, now)
            .unwrap();
        let first = change(
            &state
                .device_authority_propose(ORIGIN, now, None, None, None, now)
                .await
                .unwrap(),
        );
        let epoch = first.change.roster.roster.root_epoch.clone();
        let later = now + DEVICE_LINK_LIFETIME + 1;
        state = serde_json::from_value(serde_json::to_value(state).unwrap()).unwrap();
        state
            .device_authority_observe_at(ORIGIN, None, later, later)
            .unwrap();
        let second = change(
            &state
                .device_authority_propose(ORIGIN, later, None, None, None, later)
                .await
                .unwrap(),
        );
        assert_eq!(second.change.roster.roster.version, 2);
        assert_eq!(second.change.expected_version, 0);
        assert_eq!(second.change.roster.roster.root_epoch, epoch);
        state
            .device_authority_observe_at(ORIGIN, Some(second.change.roster), later, later)
            .unwrap();
        let c = candidate_at(&state, later);
        let signed = c.request.clone();
        let proposal = change(
            &state
                .device_authority_propose(ORIGIN, later, Some(signed), None, None, later)
                .await
                .unwrap(),
        );
        assert_eq!(proposal.change.roster.roster.highest_device_id, 2);
        let expiry = later + DEVICE_LINK_LIFETIME + 1;
        state
            .device_authority_observe_at(ORIGIN, remote(&state), expiry, expiry)
            .unwrap();
        let next = candidate_at(&state, expiry);
        let next = change(
            &state
                .device_authority_propose(ORIGIN, expiry, Some(next.request), None, None, expiry)
                .await
                .unwrap(),
        );
        assert_eq!(next.change.roster.roster.version, 4);
        assert_eq!(next.change.expected_version, 2);
        assert_eq!(next.change.roster.roster.highest_device_id, 3);
        assert!(
            state
                .device_authority
                .as_ref()
                .unwrap()
                .issued_candidates
                .len()
                == 2
        );
    });
}
#[test]
fn observed_rollback_or_missing_sidecar_never_restores_signing_authority() {
    futures::executor::block_on(async {
        let mut state = initialize().await;
        let now = current_time().unwrap();
        let original = remote(&state).unwrap();
        let mut without = state.clone();
        without.device_authority = None;
        assert!(
            without
                .device_authority_observe(ORIGIN, Some(original.clone()), now)
                .is_err()
        );
        assert!(state.device_authority_observe(ORIGIN, None, now).is_err());
        let refreshed = change(&state.device_authority_prepare(ORIGIN, now).await.unwrap());
        state.device_authority_commit(receipt(&refreshed)).unwrap();
        assert!(
            state
                .device_authority_observe(ORIGIN, Some(original), now)
                .is_err()
        );
        let mut other = state.clone();
        other
            .device_authority_observe(ORIGIN, remote(&other), now)
            .unwrap();
        let unknown = change(&other.device_authority_prepare(ORIGIN, now).await.unwrap());
        assert!(
            state
                .device_authority_observe(ORIGIN, Some(unknown.change.roster), now)
                .is_err()
        );
    });
}
#[test]
fn lease_clock_and_receipt_checks_fail_closed() {
    futures::executor::block_on(async {
        let mut state = initialize().await;
        let now = current_time().unwrap();
        let c = candidate(&state);
        assert!(
            state
                .device_authority_inspect(&c.code().unwrap(), now + 61)
                .is_err()
        );
        assert!(
            state
                .device_authority_observe(ORIGIN, remote(&state), now + DEVICE_ROSTER_LIFETIME)
                .is_err()
        );
        let proposal = change(
            &state
                .device_authority_approve(
                    &c.code().unwrap(),
                    &c.request.request.digest().unwrap(),
                    now,
                )
                .await
                .unwrap(),
        );
        let mut bad = receipt(&proposal);
        bad.messaging_available = true;
        assert!(state.device_authority_commit(bad).is_err());
        let mut bad = receipt(&proposal);
        bad.roster_hash = ZERO_HASH.into();
        assert!(state.device_authority_commit(bad).is_err());
        assert!(state.device_authority_snapshot().unwrap()["approval_code"].is_null());
        state.device_authority_commit(receipt(&proposal)).unwrap();
        let expired = now + DEVICE_ROSTER_LIFETIME + 1;
        let data = state
            .device_authority_observe_at(ORIGIN, remote(&state), expired, expired)
            .unwrap();
        assert!(data["approval_code"].is_null());
        assert!(
            state
                .device_authority_inspect_at(&c.code().unwrap(), expired, expired)
                .is_err()
        );
    });
}
#[test]
fn revocation_preserves_root_and_highwater_and_forbids_reusing_candidate() {
    futures::executor::block_on(async {
        let mut state = initialize().await;
        let now = current_time().unwrap();
        let c = candidate(&state);
        let proposal = change(
            &state
                .device_authority_approve(
                    &c.code().unwrap(),
                    &c.request.request.digest().unwrap(),
                    now,
                )
                .await
                .unwrap(),
        );
        state
            .device_authority_observe(ORIGIN, Some(proposal.change.roster), now)
            .unwrap();
        assert!(state.device_authority_revoke(1, now).await.is_err());
        let revoke = change(&state.device_authority_revoke(2, now).await.unwrap());
        assert_eq!(revoke.change.roster.roster.devices.len(), 1);
        assert_eq!(revoke.change.roster.roster.highest_device_id, 2);
        state
            .device_authority_observe(ORIGIN, Some(revoke.change.roster), now)
            .unwrap();
        assert!(
            state
                .device_authority_inspect(&c.code().unwrap(), now)
                .is_err()
        );
        let next = candidate(&state);
        let next = change(
            &state
                .device_authority_approve(
                    &next.code().unwrap(),
                    &next.request.request.digest().unwrap(),
                    now,
                )
                .await
                .unwrap(),
        );
        assert_eq!(next.change.roster.roster.highest_device_id, 3);
        assert_eq!(
            next.change.roster.roster.root_identity_key,
            state.upload.identity_key
        );
    });
}
