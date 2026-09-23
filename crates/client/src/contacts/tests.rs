use super::*;
use crate::tests::{bundle, connect, incoming, restart};

#[test]
fn removal_is_atomic_for_stale_noncanonical_unknown_and_self_targets() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("alice@gmail.com").await.unwrap();
        let bob = State::initialize("bob@gmail.com").await.unwrap();
        alice.add_contact(bundle(&bob)).await.unwrap();
        let pin = fingerprint(&bob.upload.identity_key).unwrap();
        for (email, proof) in [
            (&bob.email[..], "wrong"),
            (&bob.email, &"0".repeat(64)),
            ("Bob@gmail.com", &pin),
            ("alice@gmail.com", &pin),
            ("absent@gmail.com", &pin),
        ] {
            let before = serde_json::to_value(&alice).unwrap();
            assert_eq!(
                alice.remove_contact(email, proof).unwrap_err().to_string(),
                REMOVAL_REJECTED
            );
            assert_eq!(serde_json::to_value(&alice).unwrap(), before);
        }
        let result = alice
            .remove_contact(&bob.email, &pin.to_uppercase())
            .unwrap();
        assert_eq!(result, json!({"email":bob.email,"removed":true}));
        assert!(!alice.has_contact(&bob.email));
        let removed = serde_json::to_value(&alice).unwrap();
        assert!(alice.remove_contact(&bob.email, &pin).is_err());
        assert_eq!(serde_json::to_value(&alice).unwrap(), removed);
    });
}

#[test]
fn removal_cancels_all_group_legs_and_only_target_direct_history_preserving_other_crypto() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("alice@gmail.com").await.unwrap();
        let mut bob = State::initialize("bob@gmail.com").await.unwrap();
        let mut carol = State::initialize("carol@gmail.com").await.unwrap();
        connect(&mut alice, &mut bob).await;
        connect(&mut alice, &mut carol).await;
        let bob_pin = fingerprint(&bob.upload.identity_key).unwrap();
        let incoming_old = bob.encrypt(&alice.email, "old history").await.unwrap();
        alice.decrypt(incoming(&bob, incoming_old)).await.unwrap();
        alice.encrypt(&bob.email, "old pending").await.unwrap();
        let other_pending = alice.encrypt(&carol.email, "other pending").await.unwrap();
        let group = alice
            .create_group("Fixed", &[bob.email.clone(), carol.email.clone()])
            .unwrap();
        alice
            .encrypt_group(&group.id, "old group pending")
            .await
            .unwrap();
        let before = serde_json::to_value(&alice).unwrap();
        alice.remove_contact(&bob.email, &bob_pin).unwrap();
        let after = serde_json::to_value(&alice).unwrap();
        assert!(!alice.has_contact(&bob.email));
        assert!(!alice.sessions.0.contains_key(&bob.email));
        assert!(!alice.verified.contains(&bob.email));
        assert_eq!(alice.outbox.len(), 1);
        assert_eq!(alice.outbox[0].id, other_pending.id);
        assert!(alice.group_outbox.is_empty());
        assert!(alice.groups[&group.id].blocked);
        assert!(
            alice
                .messages
                .iter()
                .all(|message| message.group_id.is_some()
                    || (message.sender != bob.email && message.recipient != bob.email))
        );
        assert_eq!(
            alice
                .messages
                .iter()
                .find(|m| m.group_id.as_deref() == Some(&group.id))
                .unwrap()
                .status
                .as_deref(),
            Some("cancelled")
        );
        for field in [
            "prekeys",
            "signed",
            "kyber",
            "upload",
            "received",
            "logical_received",
            "self_channel",
        ] {
            assert_eq!(before[field], after[field], "changed {field}");
        }
        assert_eq!(before["identities"]["pair"], after["identities"]["pair"]);
        assert_eq!(
            before["sessions"][&carol.email],
            after["sessions"][&carol.email]
        );
        assert_eq!(
            before["identities"]["known"][&carol.email],
            after["identities"]["known"][&carol.email]
        );
        // Benign removal permits an explicit same-key re-add and new manual verification.
        alice.add_contact(bundle(&bob)).await.unwrap();
        assert!(alice.encrypt(&bob.email, "not yet verified").await.is_err());
        alice.verify_contact(&bob.email, &bob_pin).unwrap();
        assert!(alice.groups[&group.id].blocked);
        assert!(
            alice
                .encrypt_group(&group.id, "never revive")
                .await
                .is_err()
        );
        let sent = alice.encrypt(&bob.email, "verified again").await.unwrap();
        assert_eq!(
            bob.decrypt(incoming(&alice, sent))
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("verified again")
        );
    });
}

#[test]
fn warned_removal_cannot_retrust_old_pin_and_new_verified_pin_rejects_old_prekeys_without_warning()
{
    futures::executor::block_on(async {
        let mut alice = State::initialize("alice@gmail.com").await.unwrap();
        let mut old_bob = State::initialize("bob@gmail.com").await.unwrap();
        connect(&mut alice, &mut old_bob).await;
        let old_pin = fingerprint(&old_bob.upload.identity_key).unwrap();
        let old_ciphertext = old_bob
            .encrypt(&alice.email, "old delayed prekey")
            .await
            .unwrap();
        alice.block_groups_for_contact(&old_bob.email).unwrap();
        alice.remove_contact(&old_bob.email, &old_pin).unwrap();
        alice = restart(alice);
        let removed = serde_json::to_value(&alice).unwrap();
        let rejection = alice
            .decrypt(incoming(&old_bob, old_ciphertext.clone()))
            .await
            .unwrap();
        assert!(rejection.security_alert.is_some() && rejection.text.is_none());
        for field in ["identities", "sessions", "prekeys", "signed", "kyber"] {
            assert_eq!(serde_json::to_value(&alice).unwrap()[field], removed[field]);
        }
        assert!(
            alice
                .add_contact(bundle(&old_bob))
                .await
                .unwrap_err()
                .to_string()
                .contains("contact_identity_removed")
        );
        let mut fresh = State::initialize(&old_bob.email).await.unwrap();
        fresh.add_contact(bundle(&alice)).await.unwrap();
        fresh
            .verify_contact(
                &alice.email,
                &fingerprint(&alice.upload.identity_key).unwrap(),
            )
            .unwrap();
        alice.add_contact(bundle(&fresh)).await.unwrap();
        let fresh_message = fresh
            .encrypt(&alice.email, "new phone pending verification")
            .await
            .unwrap();
        let pending = incoming(&fresh, fresh_message);
        assert_eq!(
            alice
                .decrypt(pending.clone())
                .await
                .unwrap_err()
                .to_string(),
            "contact_verification_required"
        );
        alice
            .verify_contact(
                &fresh.email,
                &fingerprint(&fresh.upload.identity_key).unwrap(),
            )
            .unwrap();
        let mut different_transport = incoming(&old_bob, old_ciphertext);
        different_transport.id = uuid::Uuid::new_v4().to_string();
        let stores = serde_json::to_value(&alice).unwrap();
        let rejected = alice.decrypt(different_transport).await.unwrap();
        assert!(rejected.security_alert.is_some());
        let after = serde_json::to_value(&alice).unwrap();
        for field in ["identities", "sessions", "prekeys", "signed", "kyber"] {
            assert_eq!(after[field], stores[field]);
        }
        assert_eq!(
            alice.decrypt(pending).await.unwrap().text.as_deref(),
            Some("new phone pending verification")
        );
        let reply = alice
            .encrypt(&fresh.email, "new phone reply")
            .await
            .unwrap();
        assert_eq!(
            fresh
                .decrypt(incoming(&alice, reply))
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("new phone reply")
        );
    });
}

#[test]
fn retired_pin_records_are_bounded_and_unsafe_pins_outlive_queue_expiry_until_new_verification() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("alice@gmail.com").await.unwrap();
        let bob = State::initialize("bob@gmail.com").await.unwrap();
        alice.add_contact(bundle(&bob)).await.unwrap();
        let pin = fingerprint(&bob.upload.identity_key).unwrap();
        alice.block_groups_for_contact(&bob.email).unwrap();
        alice.remove_contact(&bob.email, &pin).unwrap();
        let expiry = alice.removed_contacts[0].expires_at;
        alice.expire_at(expiry + 1).unwrap();
        assert!(alice.removed_pin(&bob.email, &pin));
        assert!(alice.add_contact(bundle(&bob)).await.is_err());
        let fresh = State::initialize(&bob.email).await.unwrap();
        alice.add_contact(bundle(&fresh)).await.unwrap();
        alice
            .verify_contact(
                &fresh.email,
                &fingerprint(&fresh.upload.identity_key).unwrap(),
            )
            .unwrap();
        assert!(alice.removed_contacts.is_empty());
        alice.removed_contacts = (0..MAX_REMOVED)
            .map(|_| RemovedContact {
                email: "old@gmail.com".into(),
                fingerprint: pin.clone(),
                expires_at: expiry + MESSAGE_LIFETIME_SECONDS,
                unsafe_identity: false,
            })
            .collect();
        let before = serde_json::to_value(&alice).unwrap();
        assert!(
            alice
                .remove_contact(
                    &fresh.email,
                    &fingerprint(&fresh.upload.identity_key).unwrap()
                )
                .is_err()
        );
        assert_eq!(serde_json::to_value(&alice).unwrap(), before);
        alice.expire_at(expiry + MESSAGE_LIFETIME_SECONDS).unwrap();
        assert!(alice.removed_contacts.is_empty());
    });
}

#[test]
fn removal_ffi_has_safe_failure_and_v4_migrates_without_resetting_keys() {
    let (state, pin) = futures::executor::block_on(async {
        let mut alice = State::initialize("alice@gmail.com").await.unwrap();
        let bob = State::initialize("bob@gmail.com").await.unwrap();
        alice.add_contact(bundle(&bob)).await.unwrap();
        (alice, fingerprint(&bob.upload.identity_key).unwrap())
    });
    let mut legacy = serde_json::to_value(&state).unwrap();
    legacy["version"] = json!(4);
    legacy.as_object_mut().unwrap().remove("removed_contacts");
    let response: Value = serde_json::from_str(&call(&json!({"op":"remove_contact","state":legacy,"email":"bob@gmail.com","previous_fingerprint":pin}).to_string())).unwrap();
    assert_eq!(response["ok"], true);
    assert_eq!(
        response["data"],
        json!({"email":"bob@gmail.com","removed":true})
    );
    assert_eq!(response["state"]["version"], 6);
    assert_eq!(response["state"]["upload"], legacy["upload"]);
    let failure: Value = serde_json::from_str(&call(&json!({"op":"remove_contact","state":state,"email":"bob@gmail.com","previous_fingerprint":"SECRET_DO_NOT_ECHO"}).to_string())).unwrap();
    assert_eq!(failure, json!({"ok":false,"error":REMOVAL_REJECTED}));
}

#[test]
fn removing_unverified_member_discards_unknown_group_quarantine_without_display() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("alice@gmail.com").await.unwrap();
        let mut bob = State::initialize("bob@gmail.com").await.unwrap();
        let mut carol = State::initialize("carol@gmail.com").await.unwrap();
        connect(&mut alice, &mut bob).await;
        connect(&mut alice, &mut carol).await;
        let group = alice
            .create_group("Hidden roster", &[bob.email.clone(), carol.email.clone()])
            .unwrap();
        let copies = alice
            .encrypt_group(&group.id, "never promote after removal")
            .await
            .unwrap();
        let copy = copies
            .into_iter()
            .find(|copy| copy.recipient == bob.email)
            .unwrap();
        assert!(bob.decrypt(incoming(&alice, copy)).await.unwrap().deferred);
        assert_eq!(bob.deferred_groups.len(), 1);
        assert!(bob.messages.is_empty());
        bob.add_contact(bundle(&carol)).await.unwrap();
        let dedupe = serde_json::to_value(&bob.received).unwrap();
        bob.remove_contact(
            &carol.email,
            &fingerprint(&carol.upload.identity_key).unwrap(),
        )
        .unwrap();
        bob = restart(bob);
        bob.expire().unwrap();
        assert!(bob.deferred_groups.is_empty());
        assert!(bob.messages.is_empty());
        assert!(bob.groups.is_empty());
        assert_eq!(serde_json::to_value(&bob.received).unwrap(), dedupe);
    });
}

#[test]
fn legacy_replacement_also_retires_old_prekeys_before_new_session_delivery() {
    futures::executor::block_on(async {
        let mut alice = State::initialize("alice@gmail.com").await.unwrap();
        let mut bob = State::initialize("bob@gmail.com").await.unwrap();
        connect(&mut alice, &mut bob).await;
        let old = bob
            .encrypt(&alice.email, "old unseen prekey")
            .await
            .unwrap();
        let mut fresh = State::initialize(&bob.email).await.unwrap();
        fresh.add_contact(bundle(&alice)).await.unwrap();
        fresh
            .verify_contact(
                &alice.email,
                &fingerprint(&alice.upload.identity_key).unwrap(),
            )
            .unwrap();
        alice
            .replace_contact(
                &bob.email,
                bundle(&fresh),
                &fingerprint(&bob.upload.identity_key).unwrap(),
                &fingerprint(&fresh.upload.identity_key).unwrap(),
            )
            .await
            .unwrap();
        let stores = serde_json::to_value(&alice).unwrap();
        let rejected = alice.decrypt(incoming(&bob, old)).await.unwrap();
        assert!(rejected.security_alert.is_some());
        let after = serde_json::to_value(&alice).unwrap();
        for field in ["identities", "sessions", "prekeys", "signed", "kyber"] {
            assert_eq!(after[field], stores[field]);
        }
        let sent = fresh
            .encrypt(&alice.email, "fresh verified phone")
            .await
            .unwrap();
        assert_eq!(
            alice
                .decrypt(incoming(&fresh, sent))
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("fresh verified phone")
        );
    });
}
