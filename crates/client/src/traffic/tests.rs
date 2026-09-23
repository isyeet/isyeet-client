use super::*;
use crate::tests::{bundle, connect, incoming, restart, signal_frame};

async fn pair() -> (State, State, i64) {
    let mut alice = State::initialize("alice@gmail.com").await.unwrap();
    let mut bob = State::initialize("bob@gmail.com").await.unwrap();
    connect(&mut alice, &mut bob).await;
    alice.set_traffic_mode(true).unwrap();
    bob.set_traffic_mode(true).unwrap();
    let now = current_time().unwrap();
    advertise(&mut alice, &mut bob, now).await;
    advertise(&mut bob, &mut alice, now).await;
    (alice, bob, now)
}
async fn advertise(sender: &mut State, recipient: &mut State, now: i64) {
    for state in [&mut *sender, &mut *recipient] {
        if state.cover_enabled() {
            state.confirm_traffic_quiet_at(now, 0, now).unwrap();
        }
    }
    let message = sender
        .encrypt_at(&recipient.email, "Real message", now)
        .await
        .unwrap();
    recipient
        .decrypt_at(incoming(sender, message.clone()), now)
        .await
        .unwrap();
    sender.sent(&message.id).unwrap();
}

#[test]
fn cover_is_real_signal_hidden_durable_deduped_and_receipted_without_reply() {
    futures::executor::block_on(async {
        let (mut alice, mut bob, now) = pair().await;
        let before_history = bob.messages.len();
        let cover = alice.create_cover_at(&bob.email, now).await.unwrap();
        assert_eq!(decode(&cover.envelope).unwrap().len(), ENVELOPE_BYTES);
        assert_eq!(alice.cover_message_ids(), vec![cover.id.clone()]);
        assert!(alice.create_cover_at(&bob.email, now).await.is_err());
        alice = restart(alice);
        bob = restart(bob);
        let queued = incoming(&alice, cover.clone());
        let received = bob.decrypt_at(queued.clone(), now).await.unwrap();
        assert!(received.cover && received.text.is_none() && received.security_alert.is_none());
        assert_eq!(bob.messages.len(), before_history);
        assert!(bob.outbox.is_empty());
        assert!(bob.decrypt_at(queued, now).await.unwrap().duplicate);
        assert_eq!(bob.traffic.peers[&alice.email].receipts.len(), 1);
        // Receipt carried by a normal reply frees even a still-queued cover.
        advertise(&mut bob, &mut alice, now + 1).await;
        assert!(alice.cover_message_ids().is_empty());
        assert!(alice.traffic.peers[&bob.email].outstanding.is_empty());
        assert_eq!(alice.traffic.creations.len(), 1);
    });
}

#[test]
fn no_consent_no_cover_and_old_direct_parser_ignores_trailer() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("alice@gmail.com").await.unwrap();
        let mut bob = State::initialize("bob@gmail.com").await.unwrap();
        connect(&mut alice, &mut bob).await;
        alice.set_traffic_mode(true).unwrap();
        assert!(alice.cover_candidates().is_empty());
        assert!(alice.create_cover(&bob.email).await.is_err());
        let now = current_time().unwrap();
        let text = "x".repeat(MAX_TEXT_BYTES);
        let mut bytes = frame(text.as_bytes(), deadline(now).unwrap()).unwrap();
        alice.write_traffic_trailer(&bob.email, &mut bytes, deadline(now).unwrap());
        assert_eq!(
            unframe(&bytes, now).unwrap().text.as_deref(),
            Some(text.as_str())
        );
        advertise(&mut bob, &mut alice, now).await;
        assert!(alice.cover_candidates().is_empty());
        bob.set_traffic_mode(true).unwrap();
        advertise(&mut bob, &mut alice, now + 1).await;
        assert_eq!(alice.cover_candidates(), vec![bob.email.clone()]);
        let cover = alice.create_cover_at(&bob.email, now + 1).await.unwrap();
        // A receiver which switches off still silently accepts in-flight covers.
        bob.set_traffic_mode(false).unwrap();
        let incoming = bob
            .decrypt_at(incoming(&alice, cover), now + 1)
            .await
            .unwrap();
        assert!(incoming.cover && incoming.security_alert.is_none());
    });
}

#[test]
fn receipts_are_pin_and_recipient_bound_and_eight_outstanding_pause_without_ratchet_advance() {
    futures::executor::block_on(async {
        let (mut alice, mut bob, now) = pair().await;
        for _ in 0..8 {
            let cover = alice.create_cover_at(&bob.email, now).await.unwrap();
            alice.sent(&cover.id).unwrap();
        }
        let before = serde_json::to_value(&alice).unwrap();
        assert!(alice.create_cover_at(&bob.email, now).await.is_err());
        assert_eq!(serde_json::to_value(&alice).unwrap(), before);
        let mut mallory = State::initialize("mallory@gmail.com").await.unwrap();
        connect(&mut alice, &mut mallory).await;
        let expires_at = deadline(now).unwrap();
        let mut forged_receipt = frame(b"ordinary", expires_at).unwrap();
        mallory.write_traffic_trailer(&alice.email, &mut forged_receipt, expires_at);
        forged_receipt[TRAILER_OFFSET + 25] = 1;
        forged_receipt[TRAILER_OFFSET + 26..TRAILER_OFFSET + 58]
            .copy_from_slice(&alice.traffic.peers[&bob.email].outstanding[0].nonce);
        alice.learn_traffic(&mallory.email, &forged_receipt, expires_at, now);
        assert_eq!(alice.traffic.peers[&bob.email].outstanding.len(), 8);
        // After original expiry, reservations expire but fresh consent is still required.
        alice.expire_at(expires_at).unwrap();
        assert!(!alice.traffic.peers.contains_key(&bob.email));
        assert!(alice.cover_candidates_at(expires_at).is_empty());
        advertise(&mut bob, &mut alice, expires_at).await;
        assert_eq!(
            alice.cover_candidates_at(expires_at),
            vec![bob.email.clone()]
        );
    });
}

#[test]
fn eight_out_of_order_covers_survive_restart_and_one_real_reply_releases_all_slots() {
    futures::executor::block_on(async {
        let (mut alice, mut bob, now) = pair().await;
        let mut pending = Vec::new();
        for _ in 0..8 {
            let cover = alice.create_cover_at(&bob.email, now).await.unwrap();
            alice.sent(&cover.id).unwrap();
            pending.push(incoming(&alice, cover));
        }
        alice = restart(alice);
        let history_count = bob.messages.len();
        for envelope in pending.into_iter().rev() {
            let message = bob.decrypt_at(envelope, now).await.unwrap();
            assert!(message.cover && message.security_alert.is_none());
            bob = restart(bob);
        }
        assert_eq!(bob.messages.len(), history_count);
        assert_eq!(bob.traffic.peers[&alice.email].receipts.len(), 8);
        assert!(bob.outbox.is_empty());
        advertise(&mut bob, &mut alice, now + 1).await;
        assert!(alice.traffic.peers[&bob.email].outstanding.is_empty());
        assert_eq!(
            alice.traffic_snapshot()["remaining_budget"],
            CREATION_BUDGET - 8
        );
        assert_eq!(alice.cover_candidates_at(now + 1), vec![bob.email.clone()]);
    });
}

#[test]
fn consent_ordering_disable_ties_stale_retry_and_warning_cancel_only_covers() {
    futures::executor::block_on(async {
        let (mut alice, mut bob, now) = pair().await;
        let cover = alice.create_cover_at(&bob.email, now).await.unwrap();
        let real = alice.encrypt_at(&bob.email, "keep", now).await.unwrap();
        let expires_at = deadline(now).unwrap();
        let mut enabled = frame(b"enabled", expires_at).unwrap();
        bob.write_traffic_trailer(&alice.email, &mut enabled, expires_at);
        let mut disabled = enabled.clone();
        disabled[TRAILER_OFFSET + 16] = 0;
        alice.learn_traffic(&bob.email, &disabled, expires_at, now);
        alice.learn_traffic(&bob.email, &enabled, expires_at, now);
        assert!(!alice.traffic.peers[&bob.email].consent);
        assert!(!alice.outbox.iter().any(|entry| entry.id == cover.id));
        assert!(alice.outbox.iter().any(|entry| entry.id == real.id));
        assert_eq!(alice.traffic.peers[&bob.email].outstanding.len(), 1);
        advertise(&mut bob, &mut alice, now + 1).await;
        let next = alice.create_cover_at(&bob.email, now + 1).await.unwrap();
        alice.expire_at(now + 301).unwrap();
        assert!(!alice.outbox.iter().any(|entry| entry.id == next.id));
        advertise(&mut bob, &mut alice, now + 302).await;
        let next = alice.create_cover_at(&bob.email, now + 302).await.unwrap();
        alice.block_groups_for_contact(&bob.email).unwrap();
        assert!(!alice.outbox.iter().any(|entry| entry.id == next.id));
        assert!(alice.cover_candidates_at(now + 302).is_empty());
        alice
            .verify_contact(&bob.email, &fingerprint(&bob.upload.identity_key).unwrap())
            .unwrap();
        assert!(alice.cover_candidates_at(now + 302).is_empty());
    });
}

#[test]
fn expired_cover_is_consumed_without_history_or_receipts_and_malformed_does_not_learn() {
    futures::executor::block_on(async {
        let (mut alice, mut bob, now) = pair().await;
        let cover = alice.create_cover_at(&bob.email, now).await.unwrap();
        let expiry = cover.expires_at;
        let expired = bob
            .decrypt_at(incoming(&alice, cover), expiry)
            .await
            .unwrap();
        assert!(expired.cover && expired.expired && expired.text.is_none());
        assert!(bob.messages.is_empty());
        assert!(!bob.traffic.peers.contains_key(&alice.email));
        let mut invalid = frame(b"bad", deadline(deadline(now).unwrap()).unwrap()).unwrap();
        invalid[14] = 0;
        let request = alice
            .encrypt_frame(
                &bob.email,
                &invalid,
                deadline(deadline(now).unwrap()).unwrap(),
            )
            .await
            .unwrap();
        let old_advertisement = bob.traffic.peers.get(&alice.email).cloned();
        let alert = bob
            .decrypt_at(incoming(&alice, request), deadline(now).unwrap())
            .await
            .unwrap();
        assert!(alert.security_alert.is_some());
        assert!(bob.traffic.peers.get(&alice.email).cloned() == old_advertisement);
    });
}

#[test]
fn rolling_budget_and_upgrade_are_bounded_and_preserve_keys() {
    futures::executor::block_on(async {
        let (mut alice, bob, now) = pair().await;
        alice.traffic.creations = vec![now; CREATION_BUDGET];
        assert!(alice.create_cover_at(&bob.email, now).await.is_err());
        assert_eq!(alice.traffic_snapshot()["remaining_budget"], 0);
        alice.expire_at(deadline(now).unwrap()).unwrap();
        assert_eq!(
            alice.traffic_snapshot()["remaining_budget"],
            CREATION_BUDGET
        );
        let key = serde_json::to_value(alice.key_upload()).unwrap();
        let mut legacy = serde_json::to_value(&alice).unwrap();
        legacy["version"] = json!(3);
        legacy.as_object_mut().unwrap().remove("traffic");
        let mut migrated: State = serde_json::from_value(legacy).unwrap();
        migrated.expire().unwrap();
        assert_eq!(migrated.version, 6);
        assert!(!migrated.cover_enabled());
        assert_eq!(serde_json::to_value(migrated.key_upload()).unwrap(), key);
        assert!(migrated.traffic.peers.is_empty());
    });
}

#[test]
fn replaced_key_never_inherits_consent() {
    futures::executor::block_on(async {
        let (mut alice, bob, now) = pair().await;
        let cover = alice.create_cover_at(&bob.email, now).await.unwrap();
        let mut replacement = State::initialize(&bob.email).await.unwrap();
        replacement.add_contact(bundle(&alice)).await.unwrap();
        replacement
            .verify_contact(
                &alice.email,
                &fingerprint(&alice.upload.identity_key).unwrap(),
            )
            .unwrap();
        alice
            .replace_contact(
                &bob.email,
                bundle(&replacement),
                &fingerprint(&bob.upload.identity_key).unwrap(),
                &fingerprint(&replacement.upload.identity_key).unwrap(),
            )
            .await
            .unwrap();
        assert!(!alice.outbox.iter().any(|entry| entry.id == cover.id));
        assert!(alice.cover_candidates().is_empty());
        replacement.set_traffic_mode(true).unwrap();
        advertise(&mut replacement, &mut alice, now + 1).await;
        assert_eq!(alice.cover_candidates_at(now + 1), vec![bob.email.clone()]);
        let old = alice.traffic.peers[&bob.email].outstanding[0].clone();
        let mut forged = frame(
            b"new pin cannot receipt old pin",
            deadline(now + 1).unwrap(),
        )
        .unwrap();
        replacement.write_traffic_trailer(&alice.email, &mut forged, deadline(now + 1).unwrap());
        forged[TRAILER_OFFSET + 25] = 1;
        forged[TRAILER_OFFSET + 26..TRAILER_OFFSET + 58].copy_from_slice(&old.nonce);
        alice.learn_traffic(
            &replacement.email,
            &forged,
            deadline(now + 1).unwrap(),
            now + 1,
        );
        assert_eq!(alice.traffic.peers[&bob.email].outstanding.len(), 1);
    });
}

#[test]
fn group_replies_piggyback_receipts_without_changing_text_or_logical_identity() {
    futures::executor::block_on(async {
        let (mut alice, mut bob, now) = pair().await;
        let cover = alice.create_cover_at(&bob.email, now).await.unwrap();
        bob.decrypt_at(incoming(&alice, cover), now).await.unwrap();
        let group = bob
            .create_group(&"T".repeat(48), std::slice::from_ref(&alice.email))
            .unwrap();
        let text = "x".repeat(1024);
        let requests = bob.encrypt_group(&group.id, &text).await.unwrap();
        let logical_id = bob.messages.last().unwrap().logical_id.clone();
        let message = alice
            .decrypt(incoming(&bob, requests[0].clone()))
            .await
            .unwrap();
        assert_eq!(message.text.as_deref(), Some(text.as_str()));
        assert_eq!(message.logical_id, logical_id);
        assert_eq!(message.group_id, Some(group.id));
        assert!(!message.cover);
        assert!(alice.traffic.peers[&bob.email].outstanding.is_empty());
    });
}

#[test]
fn absent_or_malformed_capability_padding_does_not_hide_valid_ascii_or_grant_consent() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("alice@gmail.com").await.unwrap();
        let mut bob = State::initialize("bob@gmail.com").await.unwrap();
        connect(&mut alice, &mut bob).await;
        bob.set_traffic_mode(true).unwrap();
        alice.set_traffic_mode(true).unwrap();
        let now = current_time().unwrap();
        for malformed in 0..5 {
            let expires_at = deadline(now).unwrap();
            let mut bytes = frame(b"**literal plain text**", expires_at).unwrap();
            if malformed != 0 {
                alice.write_traffic_trailer(&bob.email, &mut bytes, expires_at);
                match malformed {
                    1 => bytes[TRAILER_OFFSET + 16] = 2,
                    2 => bytes[TRAILER_OFFSET + 25] = 9,
                    3 => bytes[TRAILER_OFFSET + 17..TRAILER_OFFSET + 25]
                        .copy_from_slice(&(now + MESSAGE_FUTURE_SKEW_SECONDS + 1).to_be_bytes()),
                    _ => bytes[TRAILER_OFFSET] = 0,
                }
            }
            let request = signal_frame(&mut alice, &bob.email, &bytes).await;
            let message = bob.decrypt_at(request, now).await.unwrap();
            assert_eq!(message.text.as_deref(), Some("**literal plain text**"));
            assert!(!message.cover);
            assert!(bob.cover_candidates_at(now).is_empty());
            assert!(bob.traffic.peers.is_empty());
        }
    });
}

#[test]
fn abi_traffic_mode_and_hidden_cover_return_full_state_without_wire_tags() {
    let (alice, bob, _) = futures::executor::block_on(pair());
    let response: Value = serde_json::from_str(&call(
        &json!({"op":"create_cover","state":alice,"recipient":bob.email}).to_string(),
    ))
    .unwrap();
    assert_eq!(response["ok"], true);
    assert_eq!(response["state"]["version"], 6);
    assert_eq!(response["data"].as_object().unwrap().len(), 4);
    let disabled: Value = serde_json::from_str(&call(
        &json!({"op":"set_traffic_mode","state":response["state"],"enabled":false}).to_string(),
    ))
    .unwrap();
    assert_eq!(disabled["data"]["traffic"]["enabled"], false);
    assert_eq!(disabled["data"]["traffic"]["outstanding"], 1);
    assert_eq!(disabled["data"]["traffic"]["cover_outbox_ids"], json!([]));
    assert_eq!(disabled["state"]["outbox"], json!([]));
}

#[test]
fn enabled_mode_requires_fresh_quiet_confirmation_for_advertising_and_cover_creation() {
    futures::executor::block_on(async {
        let (mut alice, bob, now) = pair().await;
        alice.traffic.confirmed_server_time = None;
        assert!(alice.cover_candidates_at(now).is_empty());
        assert!(alice.create_cover_at(&bob.email, now).await.is_err());
        let mut bytes = frame(b"ordinary text", deadline(now).unwrap()).unwrap();
        alice.write_traffic_trailer(&bob.email, &mut bytes, deadline(now).unwrap());
        assert_eq!(bytes[TRAILER_OFFSET + 16], 0);
        alice.confirm_traffic_quiet_at(now, 0, now).unwrap();
        assert_eq!(alice.cover_candidates_at(now), vec![bob.email.clone()]);
        alice.write_traffic_trailer(&bob.email, &mut bytes, deadline(now).unwrap());
        assert_eq!(bytes[TRAILER_OFFSET + 16], 1);
        alice.set_traffic_mode(false).unwrap();
        assert!(alice.traffic.confirmed_server_time.is_none());
        alice.set_traffic_mode(true).unwrap();
        assert!(alice.cover_candidates_at(now).is_empty());
    });
}

#[test]
fn delayed_real_ciphertext_carries_original_relay_lease_not_its_text_creation_time() {
    futures::executor::block_on(async {
        let (mut alice, mut bob, now) = pair().await;
        let request = alice
            .encrypt_at(&bob.email, "queued text", now + 250)
            .await
            .unwrap();
        assert_eq!(request.expires_at, deadline(now + 250).unwrap());
        bob.confirm_traffic_quiet_at(now + 298, 0, now + 298)
            .unwrap();
        let result = bob
            .decrypt_at(incoming(&alice, request), now + 299)
            .await
            .unwrap();
        assert_eq!(result.text.as_deref(), Some("queued text"));
        assert_eq!(bob.traffic.peers[&alice.email].advertised_at, now);
        assert_eq!(
            bob.cover_candidates_at(now + 299),
            vec![alice.email.clone()]
        );
        assert!(bob.cover_candidates_at(now + 300).is_empty());
    });
}

#[test]
fn fresh_relay_upper_bound_closes_slow_clock_lease_without_touching_human_retention() {
    futures::executor::block_on(async {
        let (mut alice, bob, now) = pair().await;
        let cover = alice.create_cover_at(&bob.email, now).await.unwrap();
        let history = serde_json::to_value(&alice.messages).unwrap();
        let human_clock = alice.last_observed_at;
        // Local clock trails relay by60s. Complete-roundtrip ceiling adds1s,
        // placing traffic time after the peer's now+300 consent deadline.
        alice
            .confirm_traffic_quiet_at(now + 300, 1, now + 240)
            .unwrap();
        assert!(alice.cover_candidates_at(now + 240).is_empty());
        assert!(!alice.outbox.iter().any(|message| message.id == cover.id));
        assert_eq!(alice.traffic.peers[&bob.email].outstanding.len(), 1);
        assert_eq!(alice.traffic.clock_upper_bound, now + 302);
        assert_eq!(alice.last_observed_at, human_clock);
        assert_eq!(serde_json::to_value(&alice.messages).unwrap(), history);
        alice = restart(alice);
        assert!(alice.cover_candidates_at(now + 240).is_empty());
    });
}

#[test]
fn invalid_quiet_clock_or_roundtrip_is_atomic_and_abi_errors_are_safe() {
    let (mut alice, _, now) = futures::executor::block_on(pair());
    let before = serde_json::to_value(&alice).unwrap();
    for (server_time, elapsed) in [
        (now, -1),
        (now, 61),
        (now - 61, 0),
        (now + 61, 0),
        (0, 0),
        (i64::MAX, 60),
    ] {
        let error = alice
            .confirm_traffic_quiet_at(server_time, elapsed, now)
            .unwrap_err();
        assert_eq!(error.to_string(), CLOCK_UNAVAILABLE);
        assert_eq!(serde_json::to_value(&alice).unwrap(), before);
    }
    alice.confirm_traffic_quiet_at(now + 60, 60, now).unwrap();
    assert_eq!(alice.traffic.clock_upper_bound, now + 121);
    assert_eq!(alice.traffic.confirmed_server_time, Some(now + 60));
    for invalid in [
        json!(-1),
        json!(61),
        json!("secret-input-do-not-echo"),
        json!(1.5),
        Value::Null,
    ] {
        let response: Value = serde_json::from_str(&call(&json!({"op":"confirm_traffic_quiet","state":before,"server_time":now,"elapsed_seconds":invalid}).to_string())).unwrap();
        assert_eq!(
            response,
            json!({"ok":false,"error":"cover_clock_unavailable"})
        );
    }
}

#[test]
fn conservative_permission_clock_never_releases_reservations_or_creation_budget_early() {
    futures::executor::block_on(async {
        let (mut alice, bob, now) = pair().await;
        let cover = alice.create_cover_at(&bob.email, now).await.unwrap();
        alice.traffic.creations = vec![now; CREATION_BUDGET];
        let local = cover.expires_at - 60;
        alice
            .confirm_traffic_quiet_at(cover.expires_at, 60, local)
            .unwrap();
        assert!(alice.traffic.clock_upper_bound > cover.expires_at);
        assert!(alice.cover_message_ids().is_empty());
        assert_eq!(alice.traffic.peers[&bob.email].outstanding.len(), 1);
        assert_eq!(alice.cover_budget(local), 0);
        assert_eq!(alice.traffic.creations.len(), CREATION_BUDGET);
        alice.expire_at(cover.expires_at).unwrap();
        assert!(
            alice
                .traffic
                .peers
                .get(&bob.email)
                .is_none_or(|peer| peer.outstanding.is_empty())
        );
        assert_eq!(alice.cover_budget(cover.expires_at), CREATION_BUDGET);
    });
}

#[test]
fn contact_removal_cancels_queued_covers_without_refunding_outstanding_budget() {
    futures::executor::block_on(async {
        let (mut alice, bob, now) = pair().await;
        let cover = alice.create_cover_at(&bob.email, now).await.unwrap();
        let budget = alice.traffic.creations.clone();
        alice
            .remove_contact(&bob.email, &fingerprint(&bob.upload.identity_key).unwrap())
            .unwrap();
        assert!(alice.cover_candidates().is_empty());
        assert!(alice.cover_message_ids().is_empty());
        assert!(!alice.outbox.iter().any(|message| message.id == cover.id));
        assert_eq!(alice.traffic.creations, budget);
        assert_eq!(alice.traffic.peers[&bob.email].outstanding.len(), 1);
        assert!(!alice.traffic.peers[&bob.email].consent);
        assert!(alice.traffic.peers[&bob.email].receipts.is_empty());
        alice.expire_at(cover.expires_at).unwrap();
        assert!(!alice.traffic.peers.contains_key(&bob.email));
    });
}
