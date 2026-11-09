use super::*;

#[cfg(not(feature = "device-linking"))]
#[test]
fn default_build_preserves_authority_watermarks_without_exposing_device_operations() {
    let state = futures::executor::block_on(State::initialize(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "alice",
    ))
    .unwrap();
    let mut serialized = serde_json::to_value(state).unwrap();
    let sidecar = json!({"version":1,"allocated_version":19,"allocated_device_id":8,"unknown_future_field":["preserve",true]});
    serialized["device_authority"] = sidecar.clone();
    let response: Value = serde_json::from_str(&call(
        &json!({"op":"snapshot","state":serialized}).to_string(),
    ))
    .unwrap();
    assert_eq!(response["ok"], true);
    assert_eq!(response["state"]["device_authority"], sidecar);
    for op in [
        "device_authority_snapshot",
        "device_authority_prepare",
        "device_authority_approve",
        "device_candidate_create",
    ] {
        let rejected: Value = serde_json::from_str(&call(
            &json!({"op":op,"state":response["state"]}).to_string(),
        ))
        .unwrap();
        assert_eq!(rejected["ok"], false);
        assert!(rejected.get("state").is_none());
    }
}

#[test]
fn uuid_identity_and_username_metadata_are_separate_and_cannot_redirect_contacts() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "alice")
            .await
            .unwrap();
        let bob = State::initialize("300db02d-b75a-4922-8759-f08a0efa5a40", "bob")
            .await
            .unwrap();
        alice.add_contact(bundle(&bob)).await.unwrap();
        assert_eq!(alice.contact_id("bob").unwrap(), bob.account_id);
        assert_eq!(alice.contact_id("@bob").unwrap(), bob.account_id);
        assert_eq!(alice.contact_id("alice").unwrap(), alice.account_id);
        assert!(alice.contact_id("Bob").is_err());
        assert!(
            alice
                .encrypt("bob", "not a protocol address")
                .await
                .is_err()
        );
        let before_pin = alice.identities.known.clone();
        let before_sessions = alice.sessions.0.clone();
        let mut renamed = bundle(&bob);
        renamed.username = "mallory".into();
        assert!(alice.add_contact(renamed).await.is_err());
        let impostor = State::initialize("aa957ded-a93d-4de8-bb7a-f495af5c7e5c", "bob")
            .await
            .unwrap();
        assert!(alice.add_contact(bundle(&impostor)).await.is_err());
        assert_eq!(alice.contact_id("bob").unwrap(), bob.account_id);
        assert_eq!(alice.identities.known, before_pin);
        assert_eq!(alice.sessions.0, before_sessions);
        let snapshot = alice.snapshot().unwrap();
        assert_eq!(snapshot["username"], "alice");
        assert_eq!(snapshot["contacts"][0]["account_id"], bob.account_id);
        assert_eq!(snapshot["contacts"][0]["username"], "bob");
    });
}

#[test]
fn invalid_or_mixed_identity_schemas_reject_before_releasing_private_state() {
    let mixed = futures::executor::block_on(async {
        let valid = "0beaac69-d53e-48d2-b5aa-dd405b7f414d";
        for account in [
            "alice@gmail.com",
            "alice",
            "0BEAAC69-D53E-48D2-B5AA-DD405B7F414D",
            "00000000-0000-1000-8000-000000000001",
        ] {
            assert!(State::initialize(account, "alice").await.is_err());
        }
        for username in [
            "AlIce",
            "ab",
            "alice@example",
            "alice\n",
            "alice\u{202e}",
            "_alice",
        ] {
            assert!(State::initialize(valid, username).await.is_err());
        }
        let state = State::initialize(valid, "alice").await.unwrap();
        let mut mixed = serde_json::to_value(&state).unwrap();
        mixed["sessions"]["old@gmail.com"] = json!("secret-state");
        mixed
    });
    let result: Value =
        serde_json::from_str(&call(&json!({"op":"snapshot","state":mixed}).to_string())).unwrap();
    assert_eq!(result["ok"], false);
    assert!(result.get("state").is_none());
    assert!(!result.to_string().contains("secret-state"));
}

pub(super) fn bundle(state: &State) -> KeyBundle {
    let upload = state.key_upload();
    let pre_key = upload
        .pre_keys
        .iter()
        .find(|key| state.prekeys.0.contains_key(&key.id))
        .cloned();
    KeyBundle {
        account_id: state.account_id.clone(),
        username: state.username.clone(),
        registration_id: upload.registration_id,
        identity_key: upload.identity_key,
        signed_pre_key: upload.signed_pre_key,
        kyber_pre_key: upload.kyber_pre_key,
        pre_key,
    }
}
pub(super) async fn connect(alice: &mut State, bob: &mut State) {
    alice.add_contact(bundle(bob)).await.unwrap();
    bob.add_contact(bundle(alice)).await.unwrap();
    alice
        .verify_contact(
            &bob.account_id,
            &fingerprint(&bob.upload.identity_key).unwrap(),
        )
        .unwrap();
    bob.verify_contact(
        &alice.account_id,
        &fingerprint(&alice.upload.identity_key).unwrap(),
    )
    .unwrap();
}
pub(super) fn incoming(sender: &State, message: SendRequest) -> QueuedMessage {
    QueuedMessage {
        id: message.id,
        sender: sender.account_id.clone(),
        envelope: message.envelope,
        created_at: 0,
    }
}
pub(super) fn restart(state: State) -> State {
    serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap()
}

#[test]
fn every_disallowed_byte_rejected_before_string() {
    for b in 0..=255u8 {
        assert_eq!(valid_text(&[b]), (0x20..=0x7e).contains(&b));
        let mut bytes = frame(b"ok", deadline(current_time().unwrap()).unwrap()).unwrap();
        bytes[14] = b;
        assert_eq!(
            unframe(&bytes, current_time().unwrap()).is_ok(),
            (0x20..=0x7e).contains(&b)
        );
    }
    assert!(!valid_text(b""));
    assert!(!valid_text(&vec![b'a'; 1025]));
    assert!(valid_text(&vec![b'a'; 1024]));
    for len in [0, 1, 6, 2047, 2049, 9000] {
        assert!(unframe(&vec![0; len], current_time().unwrap()).is_err());
    }
    let mut bytes = frame(b"ok", deadline(current_time().unwrap()).unwrap()).unwrap();
    bytes[12..14].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(unframe(&bytes, current_time().unwrap()).is_err());
}
#[test]
fn signal_roundtrip_restart_reordering_duplicates_and_verification() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let mut bob = State::initialize("300db02d-b75a-4922-8759-f08a0efa5a40", "u300db02d")
            .await
            .unwrap();
        alice.add_contact(bundle(&bob)).await.unwrap();
        assert!(alice.encrypt(&bob.account_id, "blocked").await.is_err());
        assert!(
            alice
                .verify_contact(&bob.account_id, &"00".repeat(32))
                .is_err()
        );
        connect(&mut alice, &mut bob).await;
        for round in 0..24 {
            let expected = format!("ASCII message {round}: **literal**, https://literal.example");
            let message = alice.encrypt(&bob.account_id, &expected).await.unwrap();
            assert_eq!(decode(&message.envelope).unwrap().len(), ENVELOPE_BYTES);
            alice = restart(alice);
            assert_eq!(alice.outbox.last().unwrap().envelope, message.envelope);
            let queued = incoming(&alice, message.clone());
            let received = bob.decrypt(queued.clone()).await.unwrap();
            assert_eq!(received.text.as_deref(), Some(expected.as_str()));
            bob = restart(bob);
            assert!(bob.decrypt(queued).await.unwrap().duplicate);
            alice.sent(&message.id).unwrap();
            let response = bob.encrypt(&alice.account_id, "Reply").await.unwrap();
            bob.sent(&response.id).unwrap();
            assert_eq!(
                alice
                    .decrypt(incoming(&bob, response))
                    .await
                    .unwrap()
                    .text
                    .as_deref(),
                Some("Reply")
            );
        }
        let first = alice.encrypt(&bob.account_id, "first").await.unwrap();
        let second = alice.encrypt(&bob.account_id, "second").await.unwrap();
        assert_eq!(
            bob.decrypt(incoming(&alice, second))
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("second")
        );
        assert_eq!(
            bob.decrypt(incoming(&alice, first))
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("first")
        );
        let changed_bob = State::initialize("300db02d-b75a-4922-8759-f08a0efa5a40", "u300db02d")
            .await
            .unwrap();
        assert!(alice.add_contact(bundle(&changed_bob)).await.is_err());
    });
}
#[test]
fn malformed_or_unauthenticated_messages_alert_without_destroying_session() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let mut bob = State::initialize("300db02d-b75a-4922-8759-f08a0efa5a40", "u300db02d")
            .await
            .unwrap();
        connect(&mut alice, &mut bob).await;
        let message = alice.encrypt(&bob.account_id, "survives").await.unwrap();
        let mut corrupted = incoming(&alice, message.clone());
        corrupted.id = uuid::Uuid::new_v4().to_string();
        let mut bytes = decode(&corrupted.envelope).unwrap();
        bytes[10] ^= 0xff;
        corrupted.envelope = encode(bytes);
        let rejected = bob.decrypt(corrupted.clone()).await.unwrap();
        assert!(rejected.security_alert.is_some());
        assert!(rejected.text.is_none());
        assert!(bob.decrypt(corrupted).await.unwrap().duplicate);
        assert_eq!(
            bob.decrypt(incoming(&alice, message))
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("survives")
        );
        // Encrypt an invalid inner frame with real Signal to exercise the receive-only gate.
        let mut invalid = frame(b"abc", deadline(current_time().unwrap()).unwrap()).unwrap();
        invalid[15] = 0x1b;
        let cipher = message_encrypt(
            &invalid,
            &address(&bob.account_id),
            &address(&alice.account_id),
            &mut alice.sessions,
            &mut alice.identities,
            SystemTime::now(),
            &mut rand::rngs::OsRng.unwrap_err(),
        )
        .await
        .unwrap();
        let mut envelope = vec![0; ENVELOPE_BYTES];
        envelope[0] = 1;
        envelope[1] = cipher.message_type() as u8;
        envelope[2..6].copy_from_slice(&(cipher.serialize().len() as u32).to_be_bytes());
        envelope[6..6 + cipher.serialize().len()].copy_from_slice(cipher.serialize());
        let rejected = bob
            .decrypt(QueuedMessage {
                id: uuid::Uuid::new_v4().to_string(),
                sender: alice.account_id.clone(),
                envelope: encode(envelope),
                created_at: 0,
            })
            .await
            .unwrap();
        assert!(rejected.security_alert.is_some());
        assert!(rejected.text.is_none());
        let good = alice
            .encrypt(&bob.account_id, "after invalid")
            .await
            .unwrap();
        assert_eq!(
            bob.decrypt(incoming(&alice, good))
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("after invalid")
        );
    });
}
#[test]
fn failed_ffi_request_never_returns_proposed_state_or_echoes_plaintext() {
    let value: Value = serde_json::from_str(&call("{bad")).unwrap();
    assert_eq!(value["ok"], false);
    assert!(value.get("state").is_none());
    let init: Value = serde_json::from_str(&call(
        r#"{"op":"init","account_id":"87924606-b413-4a8a-8eee-ae8868531fbb","username":"test"}"#,
    ))
    .unwrap();
    let rejected: Value = serde_json::from_str(&call(&json!({"op":"encrypt","state":init["state"],"recipient":"18ae18f2-64c2-4442-a0aa-fe2ef8d2d130","text":"secret"}).to_string())).unwrap();
    assert_eq!(rejected["ok"], false);
    assert!(!rejected.to_string().contains("secret"));
}

#[test]
fn authenticated_deadline_boundaries_and_future_clock_limits() {
    let current = current_time().unwrap();
    let expires = deadline(current).unwrap();
    let bytes = frame(b"bounded", expires).unwrap();
    assert_eq!(bytes.len(), PLAINTEXT_FRAME_BYTES);
    assert_eq!(
        unframe(&bytes, expires - 1).unwrap().text.as_deref(),
        Some("bounded")
    );
    let expired = unframe(&bytes, expires).unwrap();
    assert!(expired.text.is_none());
    assert_eq!(expired.expires_at, expires);
    assert!(
        unframe(&bytes, expires + MESSAGE_LIFETIME_SECONDS)
            .unwrap()
            .text
            .is_none()
    );
    let permitted = frame(
        b"clock",
        deadline(current + MESSAGE_FUTURE_SKEW_SECONDS).unwrap(),
    )
    .unwrap();
    assert!(unframe(&permitted, current).is_ok());
    let future = frame(
        b"clock",
        deadline(current + MESSAGE_FUTURE_SKEW_SECONDS + 1).unwrap(),
    )
    .unwrap();
    assert!(unframe(&future, current).is_err());
    for invalid in [i64::MIN, -1, 0, MESSAGE_LIFETIME_SECONDS, i64::MAX] {
        assert!(unframe(&frame(b"invalid", invalid).unwrap(), current).is_err());
    }
    assert!(deadline(i64::MAX).is_err());
}

#[test]
fn expiry_prunes_plaintext_and_pending_ciphertext_without_touching_crypto() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let mut bob = State::initialize("300db02d-b75a-4922-8759-f08a0efa5a40", "u300db02d")
            .await
            .unwrap();
        connect(&mut alice, &mut bob).await;
        let current = current_time().unwrap() + 1;
        let sent = alice
            .encrypt_at(&bob.account_id, "delete on time", current)
            .await
            .unwrap();
        let identity = serde_json::to_value(&alice.identities).unwrap();
        let sessions = serde_json::to_value(&alice.sessions).unwrap();
        let prekeys = serde_json::to_value(&alice.prekeys).unwrap();
        let verified = alice.verified.clone();
        alice.expire_at(sent.expires_at - 1).unwrap();
        assert_eq!(alice.messages.len(), 1);
        assert_eq!(alice.outbox[0].envelope, sent.envelope);
        assert_eq!(alice.outbox[0].expires_at, sent.expires_at);
        alice = restart(alice);
        alice.expire_at(sent.expires_at).unwrap();
        assert!(alice.messages.is_empty() && alice.outbox.is_empty());
        assert_eq!(serde_json::to_value(&alice.identities).unwrap(), identity);
        assert_eq!(serde_json::to_value(&alice.sessions).unwrap(), sessions);
        assert_eq!(serde_json::to_value(&alice.prekeys).unwrap(), prekeys);
        assert_eq!(alice.verified, verified);
        // A rollback of the wall clock cannot revive deleted state or lower the
        // persisted time floor, including after a restart.
        alice = restart(alice);
        alice.expire_at(current).unwrap();
        assert_eq!(alice.last_observed_at, sent.expires_at);
        assert!(alice.messages.is_empty() && alice.outbox.is_empty());
    });
}

#[test]
fn delayed_expired_ciphertext_consumes_ratchet_without_alert_or_plaintext() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let mut bob = State::initialize("300db02d-b75a-4922-8759-f08a0efa5a40", "u300db02d")
            .await
            .unwrap();
        connect(&mut alice, &mut bob).await;
        let current = current_time().unwrap() + 1;
        let message = alice
            .encrypt_at(&bob.account_id, "never display late", current)
            .await
            .unwrap();
        let expires_at = message.expires_at;
        let mut queued = incoming(&alice, message);
        // Neither extreme of untrusted relay timestamps changes authenticated expiry.
        queued.created_at = i64::MAX;
        let before = serde_json::to_value(&bob.sessions).unwrap();
        let received = bob.decrypt_at(queued.clone(), expires_at).await.unwrap();
        assert!(received.expired && !received.duplicate);
        assert!(received.text.is_none() && received.security_alert.is_none());
        assert_eq!(received.expires_at, expires_at);
        assert!(bob.messages.is_empty());
        assert_ne!(serde_json::to_value(&bob.sessions).unwrap(), before);
        bob = restart(bob);
        let tombstone = serde_json::to_value(&bob.received).unwrap();
        let replay = bob.decrypt_at(queued, expires_at + 60).await.unwrap();
        assert!(replay.duplicate && replay.text.is_none() && replay.security_alert.is_none());
        assert_eq!(serde_json::to_value(&bob.received).unwrap(), tombstone);
        let live = alice
            .encrypt_at(&bob.account_id, "after expired", expires_at + 60)
            .await
            .unwrap();
        let live = bob
            .decrypt_at(incoming(&alice, live), expires_at + 60)
            .await
            .unwrap();
        assert_eq!(live.text.as_deref(), Some("after expired"));
        assert!(!live.expired);
        bob.expire_at(expires_at + MESSAGE_LIFETIME_SECONDS)
            .unwrap();
        assert_eq!(bob.received.len(), 1);
    });
}

pub(super) async fn signal_frame(
    alice: &mut State,
    recipient: &str,
    plaintext: &[u8],
) -> QueuedMessage {
    let cipher = message_encrypt(
        plaintext,
        &address(recipient),
        &address(&alice.account_id),
        &mut alice.sessions,
        &mut alice.identities,
        SystemTime::now(),
        &mut rand::rngs::OsRng.unwrap_err(),
    )
    .await
    .unwrap();
    let mut envelope = vec![0; ENVELOPE_BYTES];
    envelope[0] = 1;
    envelope[1] = cipher.message_type() as u8;
    envelope[2..6].copy_from_slice(&(cipher.serialize().len() as u32).to_be_bytes());
    envelope[6..6 + cipher.serialize().len()].copy_from_slice(cipher.serialize());
    QueuedMessage {
        id: uuid::Uuid::new_v4().to_string(),
        sender: alice.account_id.clone(),
        envelope: encode(envelope),
        created_at: 0,
    }
}

#[test]
fn authenticated_undated_legacy_frame_is_silently_consumed() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let mut bob = State::initialize("300db02d-b75a-4922-8759-f08a0efa5a40", "u300db02d")
            .await
            .unwrap();
        connect(&mut alice, &mut bob).await;
        let mut legacy = vec![0; PLAINTEXT_FRAME_BYTES];
        legacy[..4].copy_from_slice(b"ISY1");
        legacy[4..6].copy_from_slice(&6u16.to_be_bytes());
        legacy[6..12].copy_from_slice(b"legacy");
        let queued = signal_frame(&mut alice, &bob.account_id, &legacy).await;
        let result = bob.decrypt(queued.clone()).await.unwrap();
        assert!(result.expired && result.text.is_none() && result.security_alert.is_none());
        assert!(bob.messages.is_empty());
        bob = restart(bob);
        assert!(bob.decrypt(queued).await.unwrap().duplicate);
        let valid = alice
            .encrypt(&bob.account_id, "new protocol")
            .await
            .unwrap();
        assert_eq!(
            bob.decrypt(incoming(&alice, valid))
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("new protocol")
        );
    });
}

#[test]
fn snapshot_and_history_never_expose_expired_material() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let mut bob = State::initialize("300db02d-b75a-4922-8759-f08a0efa5a40", "u300db02d")
            .await
            .unwrap();
        connect(&mut alice, &mut bob).await;
        alice
            .encrypt(&bob.account_id, "secret-expired-test")
            .await
            .unwrap();
        let expired = current_time().unwrap();
        alice.messages[0].expires_at = expired;
        alice.outbox[0].expires_at = expired;
        assert!(alice.history().unwrap().is_empty());
        let snapshot = alice.snapshot().unwrap();
        assert!(snapshot["messages"].as_array().unwrap().is_empty());
        assert!(snapshot["outbox"].as_array().unwrap().is_empty());
        let response = dispatch(json!({"op":"expire","state":alice}))
            .await
            .unwrap();
        assert_eq!(response["ok"], true);
        assert!(!response.to_string().contains("secret-expired-test"));
        assert!(response["state"]["messages"].as_array().unwrap().is_empty());
        assert!(response["state"]["outbox"].as_array().unwrap().is_empty());
    });
}

#[test]
fn pre_username_states_are_rejected_without_migrating_private_material() {
    futures::executor::block_on(async {
        let state = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "alice")
            .await
            .unwrap();
        for version in 1..=6 {
            let mut old = serde_json::to_value(&state).unwrap();
            old["version"] = json!(version);
            let mut loaded: State = serde_json::from_value(old.clone()).unwrap();
            let before = serde_json::to_value(&loaded).unwrap();
            assert!(loaded.expire().is_err());
            assert_eq!(serde_json::to_value(&loaded).unwrap(), before);
            assert!(
                dispatch(json!({"op":"snapshot","state":old}))
                    .await
                    .is_err()
            );
        }
        let mut email_state = serde_json::to_value(&state).unwrap();
        email_state.as_object_mut().unwrap().remove("account_id");
        email_state["email"] = json!("alice@gmail.com");
        assert!(serde_json::from_value::<State>(email_state).is_err());
    });
}

#[test]
fn malformed_legacy_ascii_is_rejected_without_decoding() {
    let mut legacy = vec![0; PLAINTEXT_FRAME_BYTES];
    legacy[..4].copy_from_slice(b"ISY1");
    legacy[4..6].copy_from_slice(&1u16.to_be_bytes());
    for byte in 0..=255u8 {
        legacy[6] = byte;
        assert_eq!(
            unframe(&legacy, current_time().unwrap()).is_ok(),
            (0x20..=0x7e).contains(&byte)
        );
    }
    legacy[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(unframe(&legacy, current_time().unwrap()).is_err());
}

#[test]
fn replacement_rejects_bad_proof_or_bundle_without_any_state_mutation() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let mut bob = State::initialize("300db02d-b75a-4922-8759-f08a0efa5a40", "u300db02d")
            .await
            .unwrap();
        connect(&mut alice, &mut bob).await;
        alice
            .encrypt(&bob.account_id, "pending old session")
            .await
            .unwrap();
        // Even expiry pruning on a rejected public operation must stay on its clone.
        alice.messages[0].expires_at = 1;
        alice.outbox[0].expires_at = 1;
        let replacement = State::initialize(&bob.account_id, &bob.username)
            .await
            .unwrap();
        let old = fingerprint(&bob.upload.identity_key).unwrap();
        let new = fingerprint(&replacement.upload.identity_key).unwrap();
        let fresh = bundle(&replacement);
        let mut wrong_account = fresh.clone();
        wrong_account.account_id = "aae74993-71fb-4754-abf1-3581ebd58df8".into();
        let mut wrong_account_alias = fresh.clone();
        wrong_account_alias.account_id = "d87b0ce5-f90c-409b-b822-14df2cdcad1e".into();
        let mut bad_ec_signature = fresh.clone();
        let mut signature = decode(&bad_ec_signature.signed_pre_key.signature).unwrap();
        signature[0] ^= 1;
        bad_ec_signature.signed_pre_key.signature = encode(signature);
        let mut bad_kyber_signature = fresh.clone();
        let mut signature = decode(&bad_kyber_signature.kyber_pre_key.signature).unwrap();
        signature[0] ^= 1;
        bad_kyber_signature.kyber_pre_key.signature = encode(signature);
        let mut bad_prekey = fresh.clone();
        bad_prekey.signed_pre_key.public_key = encode([0; 33]);
        let cases = [
            (
                "300db02d-b75a-4922-8759-f08a0efa5a40",
                fresh.clone(),
                "00".repeat(32),
                new.clone(),
            ),
            (
                "300db02d-b75a-4922-8759-f08a0efa5a40",
                fresh.clone(),
                old.clone(),
                "00".repeat(32),
            ),
            (
                "300db02d-b75a-4922-8759-f08a0efa5a40",
                fresh.clone(),
                old[..63].into(),
                new.clone(),
            ),
            (
                "300db02d-b75a-4922-8759-f08a0efa5a40",
                fresh.clone(),
                old.clone(),
                "z".repeat(64),
            ),
            (
                "300db02d-b75a-4922-8759-f08a0efa5a40",
                bundle(&bob),
                old.clone(),
                old.clone(),
            ),
            (
                "aae74993-71fb-4754-abf1-3581ebd58df8",
                fresh.clone(),
                old.clone(),
                new.clone(),
            ),
            (
                "300db02d-b75a-4922-8759-f08a0efa5a40",
                wrong_account,
                old.clone(),
                new.clone(),
            ),
            (
                "300db02d-b75a-4922-8759-f08a0efa5a40",
                wrong_account_alias,
                old.clone(),
                new.clone(),
            ),
            (
                "d87b0ce5-f90c-409b-b822-14df2cdcad1e",
                fresh,
                old.clone(),
                new.clone(),
            ),
            (
                "300db02d-b75a-4922-8759-f08a0efa5a40",
                bad_ec_signature,
                old.clone(),
                new.clone(),
            ),
            (
                "300db02d-b75a-4922-8759-f08a0efa5a40",
                bad_kyber_signature,
                old.clone(),
                new.clone(),
            ),
            (
                "300db02d-b75a-4922-8759-f08a0efa5a40",
                bad_prekey,
                old.clone(),
                new.clone(),
            ),
        ];
        let before = serde_json::to_value(&alice).unwrap();
        for (account_id, bundle, previous, expected) in cases {
            assert_eq!(
                alice
                    .replace_contact(account_id, bundle, &previous, &expected)
                    .await
                    .unwrap_err()
                    .to_string(),
                CONTACT_REPLACEMENT_REJECTED
            );
            assert_eq!(serde_json::to_value(&alice).unwrap(), before);
        }
    });
}

#[test]
fn verified_replacement_recovers_queued_first_message_and_preserves_other_state() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let mut bob = State::initialize("300db02d-b75a-4922-8759-f08a0efa5a40", "u300db02d")
            .await
            .unwrap();
        let mut carol = State::initialize("c36e0493-49f8-4439-aa4c-2aa333bf235f", "uc36e0493")
            .await
            .unwrap();
        connect(&mut alice, &mut bob).await;
        let current = current_time().unwrap() + 1;
        let old_message = bob
            .encrypt_at(&alice.account_id, "old history", current)
            .await
            .unwrap();
        let old_queued = incoming(&bob, old_message);
        alice.decrypt_at(old_queued.clone(), current).await.unwrap();
        alice
            .encrypt_at(&bob.account_id, "old pending", current)
            .await
            .unwrap();
        connect(&mut alice, &mut carol).await;
        let other = carol
            .encrypt_at(&alice.account_id, "other contact history", current)
            .await
            .unwrap();
        alice
            .decrypt_at(incoming(&carol, other), current)
            .await
            .unwrap();
        let other_pending = alice
            .encrypt_at(&carol.account_id, "other pending", current)
            .await
            .unwrap();

        let mut fresh_bob = State::initialize(&bob.account_id, &bob.username)
            .await
            .unwrap();
        fresh_bob.add_contact(bundle(&alice)).await.unwrap();
        fresh_bob
            .verify_contact(
                &alice.account_id,
                &fingerprint(&alice.upload.identity_key).unwrap(),
            )
            .unwrap();
        let first_new = fresh_bob
            .encrypt_at(&alice.account_id, "first from new phone", current)
            .await
            .unwrap();
        let first_queued = incoming(&fresh_bob, first_new);
        let unchanged = serde_json::to_value(&alice).unwrap();
        assert_eq!(
            alice
                .decrypt_at(first_queued.clone(), current)
                .await
                .unwrap_err()
                .to_string(),
            "contact_identity_changed"
        );
        assert_eq!(serde_json::to_value(&alice).unwrap(), unchanged);
        // Ordinary add cannot replace the pin, even with a well-signed bundle.
        assert!(alice.add_contact(bundle(&fresh_bob)).await.is_err());
        assert_eq!(serde_json::to_value(&alice).unwrap(), unchanged);

        let old_fingerprint = fingerprint(&bob.upload.identity_key).unwrap();
        let new_fingerprint = fingerprint(&fresh_bob.upload.identity_key).unwrap();
        let contact = alice
            .replace_contact(
                &bob.account_id,
                bundle(&fresh_bob),
                &old_fingerprint.to_uppercase(),
                &new_fingerprint.to_uppercase(),
            )
            .await
            .unwrap();
        assert_eq!(
            contact,
            json!({"account_id":bob.account_id,"username":bob.username,"fingerprint":new_fingerprint,"verified":true})
        );
        let replaced = serde_json::to_value(&alice).unwrap();
        for field in [
            "account_id",
            "prekeys",
            "signed",
            "kyber",
            "upload",
            "verified",
            "received",
        ] {
            assert_eq!(
                replaced[field], unchanged[field],
                "replacement changed {field}"
            );
        }
        assert_eq!(
            replaced["identities"]["pair"],
            unchanged["identities"]["pair"]
        );
        assert_eq!(
            replaced["identities"]["registration"],
            unchanged["identities"]["registration"]
        );
        assert_eq!(
            replaced["identities"]["known"][&carol.account_id],
            unchanged["identities"]["known"][&carol.account_id]
        );
        assert_eq!(
            replaced["sessions"][&carol.account_id],
            unchanged["sessions"][&carol.account_id]
        );
        assert_ne!(
            replaced["sessions"][&bob.account_id],
            unchanged["sessions"][&bob.account_id]
        );
        assert_eq!(alice.outbox.len(), 1);
        assert_eq!(
            serde_json::to_value(&alice.outbox[0]).unwrap(),
            serde_json::to_value(other_pending).unwrap()
        );
        let other_history: Vec<_> = unchanged["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["sender"] == carol.account_id || m["recipient"] == carol.account_id)
            .cloned()
            .collect();
        assert_eq!(replaced["messages"], json!(other_history));
        // A stale confirmation cannot replace the newly committed pin.
        assert!(
            alice
                .replace_contact(
                    &bob.account_id,
                    bundle(&fresh_bob),
                    &old_fingerprint,
                    &new_fingerprint
                )
                .await
                .is_err()
        );
        assert_eq!(serde_json::to_value(&alice).unwrap(), replaced);
        alice = restart(alice);
        assert!(
            alice
                .decrypt_at(old_queued, current)
                .await
                .unwrap()
                .duplicate
        );
        assert_eq!(
            alice
                .decrypt_at(first_queued, current)
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("first from new phone")
        );
        let reply = alice
            .encrypt_at(&fresh_bob.account_id, "reply to new phone", current)
            .await
            .unwrap();
        fresh_bob = restart(fresh_bob);
        assert_eq!(
            fresh_bob
                .decrypt_at(incoming(&alice, reply), current)
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("reply to new phone")
        );
        let next = fresh_bob
            .encrypt_at(&alice.account_id, "new ratchet works", current)
            .await
            .unwrap();
        assert_eq!(
            alice
                .decrypt_at(incoming(&fresh_bob, next), current)
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("new ratchet works")
        );

        // The former identity never becomes trusted again through incoming traffic.
        let stale = bob
            .encrypt_at(&alice.account_id, "old identity rejected", current)
            .await
            .unwrap();
        let before_stale = serde_json::to_value(&alice).unwrap();
        let rejected = alice
            .decrypt_at(incoming(&bob, stale), current)
            .await
            .unwrap();
        assert!(rejected.security_alert.is_some() && rejected.text.is_none());
        let after_stale = serde_json::to_value(&alice).unwrap();
        for field in ["identities", "sessions", "prekeys", "signed", "kyber"] {
            assert_eq!(after_stale[field], before_stale[field]);
        }
    });
}

#[test]
fn replacement_and_identity_change_ffi_failures_return_safe_errors_without_state() {
    let (alice, fresh_bundle, queued, old, new) = futures::executor::block_on(async {
        let mut alice = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let mut bob = State::initialize("300db02d-b75a-4922-8759-f08a0efa5a40", "u300db02d")
            .await
            .unwrap();
        connect(&mut alice, &mut bob).await;
        let old = fingerprint(&bob.upload.identity_key).unwrap();
        let mut fresh = State::initialize(&bob.account_id, &bob.username)
            .await
            .unwrap();
        fresh.add_contact(bundle(&alice)).await.unwrap();
        fresh
            .verify_contact(
                &alice.account_id,
                &fingerprint(&alice.upload.identity_key).unwrap(),
            )
            .unwrap();
        let message = fresh
            .encrypt(&alice.account_id, "DO_NOT_ECHO_PLAINTEXT")
            .await
            .unwrap();
        let new = fingerprint(&fresh.upload.identity_key).unwrap();
        (alice, bundle(&fresh), incoming(&fresh, message), old, new)
    });
    let changed: Value = serde_json::from_str(&call(
        &json!({"op":"decrypt","state":alice,"message":queued}).to_string(),
    ))
    .unwrap();
    assert_eq!(
        changed,
        json!({"ok":false,"error":"contact_identity_changed"})
    );
    let failed: Value = serde_json::from_str(&call(&json!({"op":"replace_contact","state":alice,"account_id":"300db02d-b75a-4922-8759-f08a0efa5a40","bundle":fresh_bundle,"previous_fingerprint":old,"fingerprint":"DO_NOT_ECHO"}).to_string())).unwrap();
    assert_eq!(
        failed,
        json!({"ok":false,"error":CONTACT_REPLACEMENT_REJECTED})
    );
    let success: Value = serde_json::from_str(&call(&json!({"op":"replace_contact","state":alice,"account_id":"300db02d-b75a-4922-8759-f08a0efa5a40","bundle":fresh_bundle,"previous_fingerprint":old,"fingerprint":new}).to_string())).unwrap();
    assert_eq!(success["ok"], true);
    assert_eq!(success["data"]["verified"], true);
    assert_eq!(success["data"]["fingerprint"], new);
}

#[test]
fn self_message_uses_real_signal_isolated_stores_and_relay_delivery_only() {
    futures::executor::block_on(async {
        let mut state = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let old_state = serde_json::to_value(&state).unwrap();
        assert!(old_state.get("self_channel").is_none());
        state = restart(state);
        let current = current_time().unwrap() + 1;
        let own_account = state.account_id.clone();
        let mut queued = Vec::new();
        for n in 0..6 {
            let message = state
                .encrypt_at(&own_account, &format!("self text {n}"), current)
                .await
                .unwrap();
            assert_eq!(decode(&message.envelope).unwrap().len(), ENVELOPE_BYTES);
            queued.push(incoming(&state, message));
            assert!(
                state.messages.is_empty(),
                "self send must not echo plaintext"
            );
            state = restart(state);
        }
        assert_eq!(state.outbox.len(), 6);
        for n in (0..6).rev() {
            let received = state.decrypt_at(queued[n].clone(), current).await.unwrap();
            assert_eq!(received.text, Some(format!("self text {n}")));
            assert!(received.security_alert.is_none());
            assert_eq!(received.sender, state.account_id);
            assert_eq!(received.recipient, state.account_id);
            state = restart(state);
            assert!(
                state
                    .decrypt_at(queued[n].clone(), current)
                    .await
                    .unwrap()
                    .duplicate
            );
            state.sent(&queued[n].id).unwrap();
        }
        for n in 0..24 {
            let message = state
                .encrypt_at(&own_account, "later self text", current)
                .await
                .unwrap();
            let id = message.id.clone();
            let queued = incoming(&state, message);
            state = restart(state);
            let received = state.decrypt_at(queued, current).await.unwrap();
            assert_eq!(
                received.text.as_deref(),
                Some("later self text"),
                "round {n}"
            );
            state.sent(&id).unwrap();
        }
        assert!(state.outbox.is_empty());
        assert_eq!(state.messages.len(), 30);
        let after = serde_json::to_value(&state).unwrap();
        for field in [
            "account_id",
            "identities",
            "sessions",
            "prekeys",
            "signed",
            "kyber",
            "upload",
            "verified",
        ] {
            assert_eq!(
                after[field], old_state[field],
                "self messaging altered peer store {field}"
            );
        }
        assert!(state.verified_contacts().is_empty());
    });
}

#[test]
fn self_message_rejects_invalid_ascii_forged_identity_and_corruption() {
    futures::executor::block_on(async {
        let mut state = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let current = current_time().unwrap() + 1;
        state.expire_at(current).unwrap();
        let before = serde_json::to_value(&state).unwrap();
        for text in ["", "line\nbreak", "escape\u{1b}", "unicode\u{202e}"] {
            assert!(
                state
                    .encrypt_at("0beaac69-d53e-48d2-b5aa-dd405b7f414d", text, current)
                    .await
                    .is_err()
            );
            assert_eq!(serde_json::to_value(&state).unwrap(), before);
        }
        // Only the exact immutable own account ID selects the local channel.
        let valid = state
            .encrypt_at(
                "0beaac69-d53e-48d2-b5aa-dd405b7f414d",
                "self secret not a local echo",
                current,
            )
            .await
            .unwrap();
        assert_eq!(valid.recipient, state.account_id);
        assert!(
            !serde_json::to_string(&state)
                .unwrap()
                .contains("self secret not a local echo")
        );
        let valid_queued = incoming(&state, valid);
        let mut corrupted = valid_queued.clone();
        corrupted.id = uuid::Uuid::new_v4().to_string();
        let mut bytes = decode(&corrupted.envelope).unwrap();
        bytes[10] ^= 0xff;
        corrupted.envelope = encode(bytes);
        let channel = serde_json::to_value(&state.self_channel).unwrap();
        let rejected = state.decrypt_at(corrupted, current).await.unwrap();
        assert!(rejected.text.is_none() && rejected.security_alert.is_some());
        assert_eq!(serde_json::to_value(&state.self_channel).unwrap(), channel);
        assert_eq!(
            state
                .decrypt_at(valid_queued, current)
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("self secret not a local echo")
        );

        // An untrusted relay cannot substitute a newly generated identity with
        // our own account_id. Self traffic is pinned only to our local private key.
        let mut impostor = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let forged = impostor
            .encrypt_at(
                "0beaac69-d53e-48d2-b5aa-dd405b7f414d",
                "forged replacement",
                current,
            )
            .await
            .unwrap();
        let channel = serde_json::to_value(&state.self_channel).unwrap();
        let identity = serde_json::to_value(&state.identities).unwrap();
        let rejected = state
            .decrypt_at(incoming(&impostor, forged), current)
            .await
            .unwrap();
        assert!(rejected.text.is_none() && rejected.security_alert.is_some());
        assert_eq!(serde_json::to_value(&state.self_channel).unwrap(), channel);
        assert_eq!(serde_json::to_value(&state.identities).unwrap(), identity);

        // Exercise byte rejection after successful real Signal authentication.
        let mut invalid = frame(b"abc", deadline(current).unwrap()).unwrap();
        invalid[15] = 0x1b;
        let mut identities = state.self_identities().await.unwrap();
        let cipher = message_encrypt(
            &invalid,
            &address(&state.account_id),
            &address(&state.account_id),
            &mut state.self_channel.as_mut().unwrap().outgoing,
            &mut identities,
            SystemTime::now(),
            &mut rand::rngs::OsRng.unwrap_err(),
        )
        .await
        .unwrap();
        let mut envelope = vec![0; ENVELOPE_BYTES];
        envelope[0] = 1;
        envelope[1] = cipher.message_type() as u8;
        envelope[2..6].copy_from_slice(&(cipher.serialize().len() as u32).to_be_bytes());
        envelope[6..6 + cipher.serialize().len()].copy_from_slice(cipher.serialize());
        let rejected = state
            .decrypt_at(
                QueuedMessage {
                    id: uuid::Uuid::new_v4().to_string(),
                    sender: state.account_id.clone(),
                    envelope: encode(envelope),
                    created_at: 0,
                },
                current,
            )
            .await
            .unwrap();
        assert!(rejected.text.is_none() && rejected.security_alert.is_some());
        let next = state
            .encrypt_at(
                "0beaac69-d53e-48d2-b5aa-dd405b7f414d",
                "after invalid",
                current,
            )
            .await
            .unwrap();
        assert_eq!(
            state
                .decrypt_at(incoming(&state, next), current)
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("after invalid")
        );
    });
}

#[test]
fn self_message_expiry_consumes_ratchet_without_plaintext_or_deadline_extension() {
    futures::executor::block_on(async {
        let mut state = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let current = current_time().unwrap() + 1;
        let message = state
            .encrypt_at(
                "0beaac69-d53e-48d2-b5aa-dd405b7f414d",
                "expire unseen",
                current,
            )
            .await
            .unwrap();
        let expires_at = message.expires_at;
        let queued = incoming(&state, message.clone());
        state = restart(state);
        state.expire_at(expires_at - 1).unwrap();
        assert_eq!(state.outbox[0].envelope, message.envelope);
        assert_eq!(state.outbox[0].expires_at, expires_at);
        assert!(state.messages.is_empty());
        let channel = serde_json::to_value(&state.self_channel).unwrap();
        let expired = state.decrypt_at(queued.clone(), expires_at).await.unwrap();
        assert!(expired.expired && expired.text.is_none() && expired.security_alert.is_none());
        assert!(state.outbox.is_empty() && state.messages.is_empty());
        assert_ne!(serde_json::to_value(&state.self_channel).unwrap(), channel);
        state = restart(state);
        assert!(
            state
                .decrypt_at(queued, expires_at + 60)
                .await
                .unwrap()
                .duplicate
        );
        let next = state
            .encrypt_at(
                "0beaac69-d53e-48d2-b5aa-dd405b7f414d",
                "after expiry",
                expires_at + 60,
            )
            .await
            .unwrap();
        assert_eq!(
            state
                .decrypt_at(incoming(&state, next), expires_at + 60)
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("after expiry")
        );
    });
}

#[test]
fn self_session_remains_usable_after_signal_pending_session_timeout() {
    futures::executor::block_on(async {
        let mut state = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let current = current_time().unwrap();
        let first = state
            .encrypt_at(
                "0beaac69-d53e-48d2-b5aa-dd405b7f414d",
                "queued before aging",
                current,
            )
            .await
            .unwrap();
        let queued = incoming(&state, first);
        assert_eq!(
            decode(&queued.envelope).unwrap()[1],
            2,
            "setup must finish the pending prekey handshake"
        );
        assert!(state.messages.is_empty());
        state = restart(state);
        // Exercise the actual upstream clock check, not just the application's
        // message-expiry clock. Before the handshake fix, +31 days failed here.
        for days in [31, 365] {
            let future = SystemTime::now() + std::time::Duration::from_secs(days * 86400);
            let future_seconds = future.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
            let bytes = frame(b"self after 30 days", deadline(future_seconds).unwrap()).unwrap();
            let mut identities = state.self_identities().await.unwrap();
            let cipher = message_encrypt(
                &bytes,
                &address(&state.account_id),
                &address(&state.account_id),
                &mut state.self_channel.as_mut().unwrap().outgoing,
                &mut identities,
                future,
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await
            .unwrap();
            assert_eq!(cipher.message_type() as u8, 2);
            let mut envelope = vec![0; ENVELOPE_BYTES];
            envelope[0] = 1;
            envelope[1] = cipher.message_type() as u8;
            envelope[2..6].copy_from_slice(&(cipher.serialize().len() as u32).to_be_bytes());
            envelope[6..6 + cipher.serialize().len()].copy_from_slice(cipher.serialize());
            state = restart(state);
            let received = state
                .decrypt_at(
                    QueuedMessage {
                        id: uuid::Uuid::new_v4().to_string(),
                        sender: state.account_id.clone(),
                        envelope: encode(envelope),
                        created_at: future_seconds,
                    },
                    future_seconds,
                )
                .await
                .unwrap();
            assert_eq!(received.text.as_deref(), Some("self after 30 days"));
            state = restart(state);
        }
        // Initialization never reset a pending user message: an earlier skipped
        // ciphertext still authenticates and is silently consumed as expired.
        let late = state
            .decrypt_at(queued, current + 365 * 86400 + 60)
            .await
            .unwrap();
        assert!(late.expired && late.text.is_none() && late.security_alert.is_none());
    });
}

#[test]
fn peer_ciphertext_relabelled_as_self_cannot_mutate_either_channel() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("0beaac69-d53e-48d2-b5aa-dd405b7f414d", "u0beaac69")
            .await
            .unwrap();
        let mut bob = State::initialize("300db02d-b75a-4922-8759-f08a0efa5a40", "u300db02d")
            .await
            .unwrap();
        connect(&mut alice, &mut bob).await;
        let current = current_time().unwrap() + 1;
        let self_message = alice
            .encrypt_at(
                "0beaac69-d53e-48d2-b5aa-dd405b7f414d",
                "self remains usable",
                current,
            )
            .await
            .unwrap();
        let peer_message = bob
            .encrypt_at(&alice.account_id, "real peer message", current)
            .await
            .unwrap();
        let original = incoming(&bob, peer_message);
        let mut relabelled = original.clone();
        relabelled.sender = alice.account_id.clone();
        let before = serde_json::to_value(&alice).unwrap();
        let rejected = alice.decrypt_at(relabelled, current).await.unwrap();
        assert!(rejected.text.is_none() && rejected.security_alert.is_some());
        let after = serde_json::to_value(&alice).unwrap();
        for field in [
            "identities",
            "sessions",
            "prekeys",
            "signed",
            "kyber",
            "self_channel",
        ] {
            assert_eq!(
                after[field], before[field],
                "relabelled traffic mutated {field}"
            );
        }
        assert_eq!(
            alice
                .decrypt_at(original, current)
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("real peer message")
        );
        assert_eq!(
            alice
                .decrypt_at(incoming(&alice, self_message), current)
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("self remains usable")
        );
    });
}
