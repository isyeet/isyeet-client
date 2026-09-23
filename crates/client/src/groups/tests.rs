use super::*;

#[test]
fn group_author_namespace_binds_email_even_if_two_accounts_share_a_key() {
    let group = "11".repeat(32);
    let pin = "22".repeat(32);
    let logical = uuid::Uuid::new_v4();
    assert_ne!(
        row_id(&group, "alice@gmail.com", &pin, logical),
        row_id(&group, "bob@gmail.com", &pin, logical)
    );
    assert_ne!(
        logical_key(&group, "alice@gmail.com", &pin, logical),
        logical_key(&group, "bob@gmail.com", &pin, logical)
    );
    assert_ne!(
        member_token(&GroupMember {
            email: "alice@gmail.com".into(),
            fingerprint: pin.clone()
        })
        .unwrap(),
        member_token(&GroupMember {
            email: "bob@gmail.com".into(),
            fingerprint: pin
        })
        .unwrap()
    );
}

#[test]
fn maximum_group_frame_preserves_fixed_padding_and_exact_ascii_bounds() {
    let members = (0..8)
        .map(|index| GroupMember {
            email: format!("member{index}@gmail.com"),
            fingerprint: format!("{index:064x}"),
        })
        .collect::<Vec<_>>();
    let title = "T".repeat(48);
    let nonce = [7; 16];
    let tokens = sorted_tokens(&members).unwrap();
    let group = Group {
        id: hex(&group_id(&nonce, &title, &tokens)),
        title,
        members,
        blocked: false,
        created_at: 1,
        nonce,
    };
    let now = current_time().unwrap();
    let text = "x".repeat(1024);
    let bytes = group_frame(&group, uuid::Uuid::new_v4(), deadline(now).unwrap(), &text).unwrap();
    assert_eq!(bytes.len(), 2048);
    let decoded = parse_group(&bytes, now).unwrap();
    assert_eq!(decoded.tokens.len(), 8);
    assert_eq!(decoded.title.len(), 48);
    assert_eq!(decoded.text.len(), 1024);
    let text_offset = 80 + 48 + 8 * 32;
    assert_eq!(text_offset + 1024, 1408);
    for value in 0..=255u8 {
        let mut bytes = bytes.clone();
        bytes[text_offset] = value;
        assert_eq!(
            parse_group(&bytes, now).is_ok(),
            (0x20..=0x7e).contains(&value)
        );
    }
    assert!(
        group_frame(
            &group,
            uuid::Uuid::new_v4(),
            deadline(now).unwrap(),
            &"x".repeat(1025)
        )
        .is_err()
    );
}

fn bundle(state: &State) -> KeyBundle {
    let upload = state.key_upload();
    let pre_key = upload
        .pre_keys
        .iter()
        .filter(|key| state.prekeys.0.contains_key(&key.id))
        .nth(state.identities.known.len())
        .cloned();
    KeyBundle {
        email: state.email.clone(),
        registration_id: upload.registration_id,
        identity_key: upload.identity_key,
        signed_pre_key: upload.signed_pre_key,
        kyber_pre_key: upload.kyber_pre_key,
        pre_key,
    }
}
async fn connect(a: &mut State, b: &mut State) {
    a.add_contact(bundle(b)).await.unwrap();
    b.add_contact(bundle(a)).await.unwrap();
    a.verify_contact(&b.email, &fingerprint(&b.upload.identity_key).unwrap())
        .unwrap();
    b.verify_contact(&a.email, &fingerprint(&a.upload.identity_key).unwrap())
        .unwrap();
}
fn queued(sender: &str, request: &SendRequest) -> QueuedMessage {
    QueuedMessage {
        id: request.id.clone(),
        sender: sender.to_owned(),
        envelope: request.envelope.clone(),
        created_at: 0,
    }
}
fn restart(state: State) -> State {
    serde_json::from_value(serde_json::to_value(state).unwrap()).unwrap()
}
async fn trio() -> (State, State, State) {
    let mut a = State::initialize("alice@gmail.com").await.unwrap();
    let mut b = State::initialize("bob@gmail.com").await.unwrap();
    let mut c = State::initialize("carol@gmail.com").await.unwrap();
    connect(&mut a, &mut b).await;
    connect(&mut a, &mut c).await;
    connect(&mut b, &mut c).await;
    (a, b, c)
}

#[test]
fn pairwise_group_fanout_reply_reordering_restart_and_metadata() {
    futures::executor::block_on(async {
        let (mut a, mut b, mut c) = trio().await;
        let group = a
            .create_group("ASCII group", &[b.email.clone(), c.email.clone()])
            .unwrap();
        let first = a
            .encrypt_group(&group.id, "first group text")
            .await
            .unwrap();
        let second = a
            .encrypt_group(&group.id, "second group text")
            .await
            .unwrap();
        assert_eq!(first.len(), 2);
        assert_ne!(first[0].id, first[1].id);
        assert_ne!(first[0].envelope, first[1].envelope);
        assert_eq!(first[0].expires_at, first[1].expires_at);
        assert_eq!(a.messages.len(), 2);
        let row = a.messages[0].clone();
        assert_eq!(row.recipient_count, Some(2));
        assert_eq!(row.status.as_deref(), Some("queued"));
        assert_eq!(row.sent_at, Some(row.expires_at - MESSAGE_LIFETIME_SECONDS));
        assert!(row.received_at.is_none());
        a.sent(&first[0].id).unwrap();
        assert_eq!(a.messages[0].status.as_deref(), Some("partially_accepted"));
        assert_eq!(a.messages[0].accepted_count, Some(1));
        a.sent(&first[0].id).unwrap();
        assert_eq!(a.messages[0].accepted_count, Some(1));
        a.sent(&first[1].id).unwrap();
        assert_eq!(a.messages[0].status.as_deref(), Some("relay_accepted"));
        for receiver in [&mut b, &mut c] {
            for batch in [&second, &first] {
                let leg = batch
                    .iter()
                    .find(|leg| leg.recipient == receiver.email)
                    .unwrap();
                let message = receiver.decrypt(queued(&a.email, leg)).await.unwrap();
                assert!(message.text.is_some() && message.security_alert.is_none());
                assert_eq!(message.group_id.as_deref(), Some(group.id.as_str()));
                assert_eq!(message.sender_fingerprint, row.sender_fingerprint);
                assert!(message.received_at.is_some());
                assert_eq!(message.status.as_deref(), Some("received"));
                assert!(message.accepted_count.is_none() && message.recipient_count.is_none());
                *receiver = restart(receiver.clone());
                assert!(
                    receiver
                        .decrypt(queued(&a.email, leg))
                        .await
                        .unwrap()
                        .duplicate
                );
            }
            assert_eq!(receiver.groups[&group.id].members, group.members);
            assert_eq!(receiver.messages.len(), 2);
        }
        assert_eq!(b.messages[1].id, c.messages[1].id);
        let reply = b.encrypt_group(&group.id, "reply from Bob").await.unwrap();
        for receiver in [&mut a, &mut c] {
            let leg = reply
                .iter()
                .find(|leg| leg.recipient == receiver.email)
                .unwrap();
            assert_eq!(
                receiver
                    .decrypt(queued(&b.email, leg))
                    .await
                    .unwrap()
                    .text
                    .as_deref(),
                Some("reply from Bob")
            );
        }
        assert!(
            serde_json::to_value(&first[0])
                .unwrap()
                .get("group_id")
                .is_none()
        );
    });
}

#[test]
fn unknown_members_quarantine_durably_then_resolve_without_ratchet_replay() {
    futures::executor::block_on(async {
        let (mut a, mut b, c) = trio().await;
        b.verified.remove(&c.email);
        let group = a
            .create_group("requires Carol", &[b.email.clone(), c.email.clone()])
            .unwrap();
        let sent = a
            .encrypt_group(&group.id, "hidden until verified")
            .await
            .unwrap();
        let leg = sent.iter().find(|leg| leg.recipient == b.email).unwrap();
        let before = serde_json::to_value(&b.sessions).unwrap();
        let deferred = b.decrypt(queued(&a.email, leg)).await.unwrap();
        assert!(deferred.deferred && deferred.text.is_none() && deferred.security_alert.is_none());
        assert!(b.messages.is_empty() && b.groups.is_empty());
        assert_eq!(b.deferred_groups.len(), 1);
        assert_ne!(serde_json::to_value(&b.sessions).unwrap(), before);
        let after = serde_json::to_value(&b.sessions).unwrap();
        let received_at = b.deferred_groups[0].received_at;
        let expiry = b.deferred_groups[0].expires_at;
        b = restart(b);
        assert!(b.decrypt(queued(&a.email, leg)).await.unwrap().duplicate);
        let snapshot = b.snapshot().unwrap();
        assert_eq!(snapshot["pending_group_senders"], json!([a.email]));
        assert_eq!(snapshot["next_expiry"], expiry);
        assert!(!snapshot.to_string().contains("hidden until verified"));
        b.verify_contact(&c.email, &fingerprint(&c.upload.identity_key).unwrap())
            .unwrap();
        assert_eq!(serde_json::to_value(&b.sessions).unwrap(), after);
        assert!(b.deferred_groups.is_empty());
        assert_eq!(b.messages[0].text.as_deref(), Some("hidden until verified"));
        assert_eq!(b.messages[0].received_at, Some(received_at));
        assert_eq!(b.messages[0].expires_at, expiry);
        assert_eq!(b.resolved_message_ids, vec![b.messages[0].id.clone()]);
        b = restart(b);
        b.expire().unwrap();
        assert_eq!(b.messages.len(), 1);
        assert!(b.resolved_message_ids.is_empty());
    });
}

#[test]
fn readonly_rust_views_never_promote_quarantine_without_a_persistable_transition() {
    futures::executor::block_on(async {
        let (mut a, mut b, c) = trio().await;
        b.verified.remove(&c.email);
        let group = a
            .create_group("read helper", &[b.email.clone(), c.email.clone()])
            .unwrap();
        let legs = a
            .encrypt_group(&group.id, "durable promotion only")
            .await
            .unwrap();
        let leg = legs.iter().find(|leg| leg.recipient == b.email).unwrap();
        assert!(b.decrypt(queued(&a.email, leg)).await.unwrap().deferred);
        b.verified.insert(c.email.clone());
        let before = serde_json::to_value(&b).unwrap();
        assert!(b.history().unwrap().is_empty());
        assert!(
            b.snapshot().unwrap()["messages"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(serde_json::to_value(&b).unwrap(), before);
        let transition = dispatch(json!({"op":"expire","state":b})).await.unwrap();
        assert_eq!(
            transition["data"]["messages"][0]["text"],
            "durable promotion only"
        );
        assert_eq!(
            transition["resolved_message_ids"],
            json!([transition["data"]["messages"][0]["id"]])
        );
        assert!(
            transition["state"]["deferred_groups"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    });
}

#[test]
fn version_two_upgrade_preserves_crypto_live_history_outbox_and_original_deadline() {
    futures::executor::block_on(async {
        let (mut a, mut b, _) = trio().await;
        let current = current_time().unwrap() + 1;
        let direct = a
            .encrypt_at(&b.email, "retained v2 message", current)
            .await
            .unwrap();
        let self_message = a
            .encrypt_at("alice@gmail.com", "retained v2 self", current)
            .await
            .unwrap();
        let mut legacy = serde_json::to_value(&a).unwrap();
        legacy["version"] = json!(2);
        for field in [
            "groups",
            "group_outbox",
            "logical_received",
            "deferred_groups",
            "group_identity_warnings",
        ] {
            legacy.as_object_mut().unwrap().remove(field);
        }
        let mut migrated: State = serde_json::from_value(legacy.clone()).unwrap();
        assert!(migrated.expire_at(current).unwrap());
        assert_eq!(migrated.version, 6);
        let saved = serde_json::to_value(&migrated).unwrap();
        for field in [
            "email",
            "identities",
            "sessions",
            "prekeys",
            "signed",
            "kyber",
            "upload",
            "verified",
            "outbox",
            "messages",
            "received",
            "self_channel",
        ] {
            assert_eq!(saved[field], legacy[field], "migration changed {field}");
        }
        assert!(migrated.groups.is_empty() && migrated.deferred_groups.is_empty());
        assert!(!migrated.expire_at(current).unwrap());
        assert_eq!(
            b.decrypt_at(queued(&a.email, &direct), current)
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("retained v2 message")
        );
        assert_eq!(
            migrated
                .decrypt_at(queued(&a.email, &self_message), current)
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("retained v2 self")
        );
        let mut future = saved;
        future["version"] = json!(7);
        assert!(
            dispatch(json!({"op":"expire","state":future}))
                .await
                .is_err()
        );
    });
}

#[test]
fn quarantine_expiry_and_full_capacity_allow_relay_progress() {
    futures::executor::block_on(async {
        let (mut a, mut b, c) = trio().await;
        b.verified.remove(&c.email);
        let group = a
            .create_group("quarantine cap", &[b.email.clone(), c.email.clone()])
            .unwrap();
        let current = current_time().unwrap() + 1;
        let mut first_expiry = 0;
        for index in 0..65 {
            let legs = a
                .encrypt_group_at(&group.id, "bounded pending body", current)
                .await
                .unwrap();
            let leg = legs.iter().find(|leg| leg.recipient == b.email).unwrap();
            let message = b.decrypt_at(queued(&a.email, leg), current).await.unwrap();
            if index < 64 {
                assert!(message.deferred && message.security_alert.is_none());
            } else {
                assert!(
                    !message.deferred && message.security_alert.is_some() && message.text.is_none()
                );
            }
            first_expiry = leg.expires_at;
            for leg in &legs {
                a.sent(&leg.id).unwrap();
            }
        }
        assert_eq!(b.deferred_groups.len(), 64);
        assert_eq!(b.messages.len(), 1); // Generic rejection only, no deferred text.
        let direct = a
            .encrypt_at(&b.email, "direct still works", current)
            .await
            .unwrap();
        assert_eq!(
            b.decrypt_at(queued(&a.email, &direct), current)
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("direct still works")
        );
        b = restart(b);
        b.expire_at(first_expiry).unwrap();
        assert!(b.deferred_groups.is_empty());
        assert!(
            !serde_json::to_string(&b)
                .unwrap()
                .contains("bounded pending body")
        );
        b.verify_contact(&c.email, &fingerprint(&c.upload.identity_key).unwrap())
            .unwrap();
        assert!(b.groups.is_empty() && b.messages.is_empty());
        // A first delivery after expiry never quarantines unknown members.
        a.expire_at(first_expiry).unwrap();
        let later_group = a
            .create_group("new after retirement", &[b.email.clone(), c.email.clone()])
            .unwrap();
        let legs = a
            .encrypt_group_at(&later_group.id, "late unknown", first_expiry)
            .await
            .unwrap();
        let leg = legs.iter().find(|leg| leg.recipient == b.email).unwrap();
        b.verified.remove(&c.email);
        let message = b
            .decrypt_at(queued(&a.email, leg), leg.expires_at)
            .await
            .unwrap();
        assert!(message.expired && message.text.is_none() && !message.deferred);
        assert!(b.deferred_groups.is_empty());
    });
}

#[test]
fn fanout_preflight_and_late_signal_failure_are_atomic() {
    futures::executor::block_on(async {
        let (mut a, b, c) = trio().await;
        let group = a
            .create_group("atomic fanout", &[b.email.clone(), c.email.clone()])
            .unwrap();
        let current = current_time().unwrap() + 1;
        a.expire_at(current).unwrap();
        for _ in 0..15 {
            a.encrypt_at(&b.email, "pending", current).await.unwrap();
        }
        let before = serde_json::to_value(&a).unwrap();
        assert!(
            a.encrypt_group_at(&group.id, "no room", current)
                .await
                .is_err()
        );
        assert_eq!(serde_json::to_value(&a).unwrap(), before);
        a.outbox.clear();
        a.sessions
            .0
            .insert(c.email.clone(), encode(b"invalid later peer session"));
        let before = serde_json::to_value(&a).unwrap();
        assert!(
            a.encrypt_group_at(&group.id, "first leg must roll back", current)
                .await
                .is_err()
        );
        assert_eq!(serde_json::to_value(&a).unwrap(), before);
        a.verified.remove(&c.email);
        let before = serde_json::to_value(&a).unwrap();
        assert_eq!(
            a.encrypt_group_at(&group.id, "blocked", current)
                .await
                .unwrap_err()
                .to_string(),
            "group_blocked"
        );
        assert_eq!(serde_json::to_value(&a).unwrap(), before);
    });
}

#[test]
fn changed_member_blocks_group_and_cancels_every_pending_fanout_leg() {
    futures::executor::block_on(async {
        let (mut a, b, c) = trio().await;
        let group = a
            .create_group("old roster", &[b.email.clone(), c.email.clone()])
            .unwrap();
        let unrelated = a
            .create_group("still current", std::slice::from_ref(&c.email))
            .unwrap();
        let affected = a
            .encrypt_group(&group.id, "retain cancelled history")
            .await
            .unwrap();
        let unaffected = a
            .encrypt_group(&unrelated.id, "unaffected group")
            .await
            .unwrap();
        let direct = a.encrypt(&c.email, "unaffected direct").await.unwrap();
        a.sent(&affected[0].id).unwrap();
        a.block_groups_for_contact(&b.email).unwrap();
        assert!(a.groups[&group.id].blocked);
        assert!(!a.groups[&unrelated.id].blocked);
        assert!(
            affected
                .iter()
                .all(|leg| !a.outbox.iter().any(|pending| pending.id == leg.id))
        );
        assert_eq!(a.outbox.len(), unaffected.len() + 1);
        assert!(a.outbox.iter().any(|pending| pending.id == direct.id));
        assert_eq!(a.messages[0].status.as_deref(), Some("cancelled"));
        assert_eq!(a.messages[0].accepted_count, Some(1));
        let fresh = State::initialize(&b.email).await.unwrap();
        a.replace_contact(
            &b.email,
            bundle(&fresh),
            &fingerprint(&b.upload.identity_key).unwrap(),
            &fingerprint(&fresh.upload.identity_key).unwrap(),
        )
        .await
        .unwrap();
        assert!(a.groups[&group.id].blocked);
        assert_eq!(
            a.messages[0].text.as_deref(),
            Some("retain cancelled history")
        );
        assert!(a.encrypt_group(&group.id, "cannot revive").await.is_err());
        assert!(
            a.encrypt_group(&unrelated.id, "other roster works")
                .await
                .is_ok()
        );
    });
}

#[test]
fn logical_dedupe_rejects_conflicting_reuse_and_ignores_padding_changes() {
    futures::executor::block_on(async {
        let (mut a, mut b, c) = trio().await;
        let group = a
            .create_group("dedupe", &[b.email.clone(), c.email.clone()])
            .unwrap();
        let now = current_time().unwrap();
        let logical = uuid::Uuid::new_v4();
        let frame = group_frame(&group, logical, deadline(now).unwrap(), "original").unwrap();
        for round in 0..3 {
            let bytes = if round == 2 {
                group_frame(&group, logical, deadline(now).unwrap(), "conflict").unwrap()
            } else {
                let mut frame = frame.clone();
                frame[2047] ^= round;
                frame
            };
            let leg = a
                .encrypt_frame(&b.email, &bytes, deadline(now).unwrap())
                .await
                .unwrap();
            let message = b.decrypt(queued(&a.email, &leg)).await.unwrap();
            match round {
                0 => assert_eq!(message.text.as_deref(), Some("original")),
                1 => assert!(message.duplicate && message.text.is_none()),
                _ => assert!(message.security_alert.is_some() && message.text.is_none()),
            }
        }
        assert_eq!(
            b.messages
                .iter()
                .filter(|message| message.group_id.is_some())
                .count(),
            1
        );
    });
}

#[test]
fn authenticated_bad_group_frames_reject_without_trusting_roster() {
    futures::executor::block_on(async {
        let (mut a, mut b, c) = trio().await;
        let group = a
            .create_group("tamper", &[b.email.clone(), c.email.clone()])
            .unwrap();
        let now = current_time().unwrap();
        let good = group_frame(
            &group,
            uuid::Uuid::new_v4(),
            deadline(now).unwrap(),
            "ascii",
        )
        .unwrap();
        let token_offset = 80 + group.title.len();
        let text_offset = token_offset + group.members.len() * 32;
        let mut cases = Vec::new();
        for (index, value) in [
            (76, 49),
            (77, 1),
            (77, 9),
            (80, 0x1b),
            (text_offset, 0xff),
            (44, good[44] ^ 1),
            (token_offset, good[token_offset] ^ 1),
        ] {
            let mut bytes = good.clone();
            bytes[index] = value;
            cases.push(bytes);
        }
        let mut duplicate = good.clone();
        duplicate.copy_within(token_offset..token_offset + 32, token_offset + 32);
        cases.push(duplicate);
        let mut nil_uuid = good.clone();
        nil_uuid[12..28].fill(0);
        cases.push(nil_uuid);
        // A fully consistent descriptor still must include recipient and sender.
        for removed in [&a.email, &b.email] {
            let mut fake = group.clone();
            fake.members.retain(|member| &member.email != removed);
            fake.id = hex(&group_id(
                &fake.nonce,
                &fake.title,
                &sorted_tokens(&fake.members).unwrap(),
            ));
            cases.push(
                group_frame(
                    &fake,
                    uuid::Uuid::new_v4(),
                    deadline(now).unwrap(),
                    "missing member",
                )
                .unwrap(),
            );
        }
        for bytes in cases {
            let leg = a
                .encrypt_frame(&b.email, &bytes, deadline(now).unwrap())
                .await
                .unwrap();
            let rejected = b.decrypt(queued(&a.email, &leg)).await.unwrap();
            assert!(rejected.text.is_none() && rejected.security_alert.is_some());
            assert!(
                rejected.sent_at.is_none()
                    && rejected.sender_fingerprint.is_none()
                    && rejected.group_id.is_none()
            );
            assert!(b.groups.is_empty() && b.deferred_groups.is_empty());
        }
        let direct = a.encrypt(&b.email, "after bad group").await.unwrap();
        assert_eq!(
            b.decrypt(queued(&a.email, &direct))
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("after bad group")
        );
    });
}

#[test]
fn empty_group_retirement_frees_capacity_but_cannot_revive_blocked_current_roster() {
    futures::executor::block_on(async {
        let (mut a, mut b, c) = trio().await;
        let current = current_time().unwrap() + 1;
        a.expire_at(current).unwrap();
        b.expire_at(current).unwrap();
        let incoming_group = a
            .create_group("incoming", &[b.email.clone(), c.email.clone()])
            .unwrap();
        for _ in 0..32 {
            b.create_group("bounded", std::slice::from_ref(&a.email))
                .unwrap();
        }
        let before = serde_json::to_value(&b).unwrap();
        assert!(
            b.create_group("over capacity", std::slice::from_ref(&a.email))
                .is_err()
        );
        assert_eq!(serde_json::to_value(&b).unwrap(), before);
        let legs = a
            .encrypt_group_at(&incoming_group.id, "capacity reject", current)
            .await
            .unwrap();
        let leg = legs.iter().find(|leg| leg.recipient == b.email).unwrap();
        let rejected = b.decrypt_at(queued(&a.email, leg), current).await.unwrap();
        assert!(rejected.security_alert.is_some() && !rejected.deferred);
        b.expire_at(current + MESSAGE_LIFETIME_SECONDS).unwrap();
        assert!(b.groups.is_empty());
        let group = b
            .create_group("blocked", std::slice::from_ref(&a.email))
            .unwrap();
        b.block_groups_for_contact(&a.email).unwrap();
        b.expire_at(current + MESSAGE_LIFETIME_SECONDS * 2).unwrap();
        assert!(b.groups.contains_key(&group.id));
        let fresh = State::initialize(&a.email).await.unwrap();
        b.replace_contact(
            &a.email,
            bundle(&fresh),
            &fingerprint(&a.upload.identity_key).unwrap(),
            &fingerprint(&fresh.upload.identity_key).unwrap(),
        )
        .await
        .unwrap();
        b.expire_at(current + MESSAGE_LIFETIME_SECONDS * 2).unwrap();
        assert!(!b.groups.contains_key(&group.id));
    });
}

#[test]
fn warning_before_discovery_or_promotion_cannot_be_cleared_by_old_pin_verification() {
    futures::executor::block_on(async {
        let (mut a, mut b, c) = trio().await;
        b.verified.remove(&c.email);
        let group = a
            .create_group("not discovered yet", &[b.email.clone(), c.email.clone()])
            .unwrap();
        let sent = a
            .encrypt_group(&group.id, "must stay hidden")
            .await
            .unwrap();
        let leg = sent.iter().find(|leg| leg.recipient == b.email).unwrap();
        assert!(b.decrypt(queued(&a.email, leg)).await.unwrap().deferred);
        // Simulate a durable pre-upgrade verified pin with an external warning.
        // The warning operation must run before automatic expiry/resolution.
        b.verified.insert(c.email.clone());
        let old_pin = fingerprint(&c.upload.identity_key).unwrap();
        let blocked = dispatch(json!({"op":"block_groups_for_contact","state":b,"email":c.email,"fingerprint":old_pin})).await.unwrap();
        assert!(
            blocked["resolved_message_ids"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        b = serde_json::from_value(blocked["state"].clone()).unwrap();
        assert!(b.groups.is_empty() && b.messages.is_empty());
        b.verify_contact(&c.email, &old_pin).unwrap();
        assert_eq!(b.deferred_groups.len(), 1);
        assert!(b.messages.is_empty());
        let fresh_group = a
            .create_group("new warned descriptor", &[b.email.clone(), c.email.clone()])
            .unwrap();
        let sent = a
            .encrypt_group(&fresh_group.id, "also hidden")
            .await
            .unwrap();
        let leg = sent.iter().find(|leg| leg.recipient == b.email).unwrap();
        assert!(b.decrypt(queued(&a.email, leg)).await.unwrap().deferred);
        b = restart(b);
        b.expire().unwrap();
        assert!(b.groups.is_empty() && b.messages.is_empty());
        let fresh = State::initialize(&c.email).await.unwrap();
        let new_pin = fingerprint(&fresh.upload.identity_key).unwrap();
        b.replace_contact(&c.email, bundle(&fresh), &old_pin, &new_pin)
            .await
            .unwrap();
        assert!(!b.group_identity_warnings.contains_key(&c.email));
        // A stale sidecar recovered after a successful pin replacement is a no-op.
        let recovered = dispatch(json!({"op":"block_groups_for_contact","state":b,"email":c.email,"fingerprint":old_pin})).await.unwrap();
        b = serde_json::from_value(recovered["state"].clone()).unwrap();
        assert!(!b.group_identity_warnings.contains_key(&c.email));
        assert!(b.messages.is_empty());
        a.replace_contact(&c.email, bundle(&fresh), &old_pin, &new_pin)
            .await
            .unwrap();
        let current_group = a
            .create_group("verified new roster", &[b.email.clone(), c.email.clone()])
            .unwrap();
        let sent = a
            .encrypt_group(&current_group.id, "new pin allowed")
            .await
            .unwrap();
        let leg = sent.iter().find(|leg| leg.recipient == b.email).unwrap();
        assert_eq!(
            b.decrypt(queued(&a.email, leg))
                .await
                .unwrap()
                .text
                .as_deref(),
            Some("new pin allowed")
        );
    });
}

#[test]
fn direct_metadata_is_historical_and_legacy_or_invalid_metadata_remains_absent() {
    futures::executor::block_on(async {
        let (mut a, mut b, _) = trio().await;
        let message = a.encrypt(&b.email, "metadata").await.unwrap();
        assert_eq!(a.messages[0].status.as_deref(), Some("queued"));
        a.sent(&message.id).unwrap();
        assert_eq!(a.messages[0].status.as_deref(), Some("relay_accepted"));
        assert_eq!(a.messages[0].accepted_count, Some(1));
        let received = b.decrypt(queued(&a.email, &message)).await.unwrap();
        assert_eq!(
            received.sent_at,
            Some(message.expires_at - MESSAGE_LIFETIME_SECONDS)
        );
        assert!(received.received_at.is_some());
        assert_eq!(
            received.sender_fingerprint,
            Some(fingerprint(&a.upload.identity_key).unwrap())
        );
        let mut legacy = serde_json::to_value(&received).unwrap();
        for field in [
            "group_id",
            "logical_id",
            "sent_at",
            "received_at",
            "sender_fingerprint",
            "status",
            "accepted_count",
            "recipient_count",
            "deferred",
        ] {
            legacy.as_object_mut().unwrap().remove(field);
        }
        let legacy: LocalMessage = serde_json::from_value(legacy).unwrap();
        assert!(
            legacy.sent_at.is_none()
                && legacy.received_at.is_none()
                && legacy.sender_fingerprint.is_none()
                && legacy.status.is_none()
                && !legacy.deferred
        );
        let invalid = QueuedMessage {
            id: uuid::Uuid::new_v4().to_string(),
            sender: a.email.clone(),
            envelope: "invalid".into(),
            created_at: i64::MAX,
        };
        let alert = b.decrypt(invalid).await.unwrap();
        assert!(alert.security_alert.is_some());
        assert!(
            alert.sent_at.is_none()
                && alert.received_at.is_none()
                && alert.sender_fingerprint.is_none()
                && alert.status.is_none()
        );
    });
}
