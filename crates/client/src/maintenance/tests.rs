use super::*;
use crate::tests::{bundle, incoming, restart};
async fn initialized(email: &str) -> Result<State> {
    let mut state = State::initialize(email).await?;
    state.confirm_initial_upload()?;
    Ok(state)
}
fn inventory(state: &State, generation: u32) -> isyeet_wire::KeyMaintenanceState {
    isyeet_wire::KeyMaintenanceState {
        generation,
        keys: state.key_upload(),
    }
}
fn receipt(request: &KeyMaintenanceRequest) -> KeyMaintenanceResponse {
    KeyMaintenanceResponse {
        operation_id: request.operation_id.clone(),
        generation: request.expected_generation + 1,
    }
}
fn serialized(state: &State) -> Vec<u8> {
    serde_json::to_vec(state).unwrap()
}

#[test]
fn topup_is_durable_exact_retry_and_confirmation_is_atomic() {
    futures::executor::block_on(async {
        let mut state = initialized("alice@gmail.com").await.unwrap();
        let now = current_time().unwrap();
        let original_identity = state.upload.identity_key.clone();
        let mut remote = inventory(&state, 0);
        remote.keys.pre_keys.truncate(5);
        let request = state
            .prepare_key_maintenance_at(remote.clone(), now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.keys.pre_keys.len(), 27);
        assert!(request.keys.pre_keys.iter().all(|key| key.id > 32));
        assert_eq!(request.keys.identity_key, original_identity);
        assert_eq!(request.keys.signed_pre_key, remote.keys.signed_pre_key);
        for key in &request.keys.pre_keys {
            assert_eq!(
                encode(
                    state
                        .prekeys
                        .get_pre_key(key.id.into())
                        .await
                        .unwrap()
                        .public_key()
                        .unwrap()
                        .serialize()
                ),
                key.public_key
            );
        }
        state = restart(state);
        assert_eq!(
            serde_json::to_value(
                state
                    .prepare_key_maintenance_at(remote.clone(), now + 5000)
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            serde_json::to_value(&request).unwrap()
        );
        let saved = serialized(&state);
        let mut invalid = receipt(&request);
        invalid.generation += 1;
        assert!(
            state
                .confirm_key_maintenance_at(invalid, now + 5000)
                .is_err()
        );
        assert_eq!(serialized(&state), saved);
        let mut invalid = receipt(&request);
        invalid.operation_id = uuid::Uuid::new_v4().to_string();
        assert!(
            state
                .confirm_key_maintenance_at(invalid, now + 5000)
                .is_err()
        );
        assert_eq!(serialized(&state), saved);
        state
            .confirm_key_maintenance_at(receipt(&request), now + 5000)
            .unwrap();
        assert!(state.pending_key_maintenance().is_none());
        assert_eq!(state.upload.pre_keys.len(), 32);
        assert_eq!(state.upload.identity_key, original_identity);
        assert_eq!(state.key_maintenance.retired_ec.len(), 27);
        let remote = inventory(&state, 1);
        assert!(
            state
                .prepare_key_maintenance_at(remote, now + 5001)
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn rotate_retains_old_setup_for_thirty_day_session_and_seven_day_queue() {
    futures::executor::block_on(async {
        let mut bob = initialized("bob@gmail.com").await.unwrap();
        let mut alice = initialized("alice@gmail.com").await.unwrap();
        let now = current_time().unwrap();
        // Alice obtains Bob's prior epoch immediately before it is replaced.
        alice.add_contact(bundle(&bob)).await.unwrap();
        alice
            .verify_contact(&bob.email, &fingerprint(&bob.upload.identity_key).unwrap())
            .unwrap();
        bob.add_contact(bundle(&alice)).await.unwrap();
        bob.verify_contact(
            &alice.email,
            &fingerprint(&alice.upload.identity_key).unwrap(),
        )
        .unwrap();
        bob.key_maintenance.rotated_at = now - ROTATION_SECONDS;
        let mut remote = inventory(&bob, 0);
        remote.keys.pre_keys.remove(0); // claimed by Alice
        let request = bob
            .prepare_key_maintenance_at(remote, now)
            .await
            .unwrap()
            .unwrap();
        assert!(request.keys.pre_keys.is_empty());
        assert_ne!(request.keys.signed_pre_key.id, 1);
        assert_ne!(request.keys.kyber_pre_key.id, 1);
        bob.confirm_key_maintenance_at(receipt(&request), now)
            .unwrap();
        bob = restart(bob);
        // Still a genuine Signal message under the old signed/KEM/EC keys.
        let sent_at = now + 29 * 86400;
        let message = alice
            .encrypt_at(&bob.email, "late setup", sent_at)
            .await
            .unwrap();
        let received = bob
            .decrypt_at(
                incoming(&alice, message),
                sent_at + MESSAGE_LIFETIME_SECONDS - 1,
            )
            .await
            .unwrap();
        assert_eq!(received.text.as_deref(), Some("late setup"));
        assert!(bob.signed.0.contains_key(&1));
        assert!(bob.kyber.records.contains_key(&1));
        assert!(!bob.kyber.used.is_empty());
        bob.expire_at(now + RETENTION_SECONDS).unwrap();
        assert!(!bob.signed.0.contains_key(&1));
        assert!(!bob.kyber.records.contains_key(&1));
        assert!(bob.kyber.used.iter().all(|entry| !entry.starts_with("1:")));
        assert_eq!(bob.upload.identity_key, request.keys.identity_key);
        assert!(bob.identities.known.contains_key(&alice.email));
    });
}

#[test]
fn fresh_rotated_bundle_real_signal_roundtrip_and_no_identity_change() {
    futures::executor::block_on(async {
        let mut bob = initialized("bob@gmail.com").await.unwrap();
        let now = current_time().unwrap();
        let pair = bob.identities.pair.clone();
        bob.key_maintenance.rotated_at = 0;
        let mut remote = inventory(&bob, 0);
        remote.keys.pre_keys.clear();
        let request = bob
            .prepare_key_maintenance_at(remote, now)
            .await
            .unwrap()
            .unwrap();
        bob.confirm_key_maintenance_at(receipt(&request), now)
            .unwrap();
        let mut carol = initialized("carol@gmail.com").await.unwrap();
        crate::tests::connect(&mut carol, &mut bob).await;
        let outgoing = carol.encrypt(&bob.email, "new epoch").await.unwrap();
        assert_eq!(
            bob.decrypt(incoming(&carol, outgoing))
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("new epoch")
        );
        let reply = bob.encrypt(&carol.email, "reply").await.unwrap();
        assert_eq!(
            carol
                .decrypt(incoming(&bob, reply))
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("reply")
        );
        assert_eq!(bob.identities.pair, pair);
    });
}

#[test]
fn invalid_inventory_and_capacity_fail_without_mutation() {
    futures::executor::block_on(async {
        let mut state = initialized("alice@gmail.com").await.unwrap();
        state.expire().unwrap();
        let now = current_time().unwrap();
        let good = inventory(&state, 0);
        for variant in 0..6 {
            let mut remote = good.clone();
            match variant {
                0 => remote.keys.identity_key = "invalid".into(),
                1 => remote.keys.registration_id += 1,
                2 => remote.keys.signed_pre_key.signature = "invalid".into(),
                3 => remote.keys.kyber_pre_key.id += 1,
                4 => remote.keys.pre_keys.push(remote.keys.pre_keys[0].clone()),
                _ => remote.keys.pre_keys[0].public_key = "invalid".into(),
            }
            let before = serialized(&state);
            assert!(state.prepare_key_maintenance_at(remote, now).await.is_err());
            assert_eq!(serialized(&state), before);
        }
        state.key_maintenance.generation = Some(7);
        assert!(
            state
                .prepare_key_maintenance_at(good.clone(), now)
                .await
                .is_err()
        );
        state.key_maintenance.generation = None;
        let record = state.prekeys.0[&1].clone();
        for id in 1000..(1000 + MAX_EC_RECORDS as u32 - 32) {
            state.prekeys.0.insert(id, record.clone());
        }
        let mut remote = good;
        remote.keys.pre_keys.clear();
        let before = serialized(&state);
        assert!(state.prepare_key_maintenance_at(remote, now).await.is_err());
        assert_eq!(serialized(&state), before);
    });
}

#[test]
fn claimed_prekeys_retire_once_and_ids_never_reused() {
    futures::executor::block_on(async {
        let mut state = initialized("alice@gmail.com").await.unwrap();
        let now = current_time().unwrap();
        let mut remote = inventory(&state, 0);
        remote.keys.pre_keys.remove(0);
        assert!(
            state
                .prepare_key_maintenance_at(remote.clone(), now)
                .await
                .unwrap()
                .is_none()
        );
        let expires = state.key_maintenance.retired_ec[&1];
        assert!(
            state
                .prepare_key_maintenance_at(remote.clone(), now + 100)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(state.key_maintenance.retired_ec[&1], expires);
        state.expire_at(expires).unwrap();
        assert!(!state.prekeys.0.contains_key(&1));
        remote.keys.pre_keys.clear();
        let request = state
            .prepare_key_maintenance_at(remote, expires)
            .await
            .unwrap()
            .unwrap();
        assert!(request.keys.pre_keys.iter().all(|key| key.id > 32));
    });
}

#[test]
fn v5_migration_rotates_immediately_preserving_identity_and_downgrade_guard() {
    futures::executor::block_on(async {
        let original = initialized("alice@gmail.com").await.unwrap();
        let identity = original.identities.pair.clone();
        let mut value = serde_json::to_value(&original).unwrap();
        value["version"] = json!(5);
        value.as_object_mut().unwrap().remove("key_maintenance");
        let mut state: State = serde_json::from_value(value).unwrap();
        state.expire().unwrap();
        assert_eq!(state.version, 6);
        let remote = inventory(&state, 0);
        let request = state
            .prepare_key_maintenance(remote)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(request.keys.signed_pre_key.id, 1);
        assert_eq!(state.identities.pair, identity);
        let response = dispatch(
            json!({"op":"confirm_key_maintenance","state":state,"receipt":receipt(&request)}),
        )
        .await
        .unwrap();
        assert_eq!(response["ok"], true);
        assert!(response["data"]["key_maintenance"]["pending"].is_null());
        assert_eq!(response["state"]["version"], 6);
    });
}

#[test]
fn fresh_login_accepts_only_known_current_or_journaled_keys_and_initial_flag_is_explicit() {
    futures::executor::block_on(async {
        let mut state = State::initialize("alice@gmail.com").await.unwrap();
        assert!(state.initial_upload_pending());
        let before = serialized(&state);
        assert!(
            state
                .prepare_key_maintenance(inventory(&state, 0))
                .await
                .is_err()
        );
        assert_eq!(serialized(&state), before);
        state.confirm_initial_upload().unwrap();
        let mut remote = state.key_upload();
        remote.pre_keys.truncate(4);
        state.validate_registered_keys(&remote).unwrap();
        state.key_maintenance.rotated_at = 0;
        let request = state
            .prepare_key_maintenance(isyeet_wire::KeyMaintenanceState {
                generation: 0,
                keys: remote.clone(),
            })
            .await
            .unwrap()
            .unwrap();
        state.validate_registered_keys(&remote).unwrap(); // request not yet applied
        let mut committed = request.keys.clone();
        committed.pre_keys.extend(remote.pre_keys.clone());
        state.validate_registered_keys(&committed).unwrap(); // applied, response lost
        for variant in 0..5 {
            let mut wrong = committed.clone();
            match variant {
                0 => wrong.identity_key = "DO_NOT_ECHO".into(),
                1 => wrong.registration_id += 1,
                2 => wrong.signed_pre_key.signature = "DO_NOT_ECHO".into(),
                3 => wrong.kyber_pre_key = remote.kyber_pre_key.clone(),
                _ => wrong.pre_keys[0].public_key = "DO_NOT_ECHO".into(),
            }
            let original = serialized(&state);
            assert_eq!(
                state
                    .validate_registered_keys(&wrong)
                    .unwrap_err()
                    .to_string(),
                REJECTED
            );
            assert_eq!(serialized(&state), original);
        }
    });
}
