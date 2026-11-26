//! End-to-end behaviour of [`Session`]: several devices, each with its own encrypted store on disk,
//! exchanging the bytes a delivery service would carry.

use raindrop_crypto::backup::{self, RecoveryKey};
use raindrop_crypto::identity::safety_number;
use raindrop_crypto::{CryptoError, Incoming, Session};
use tempfile::TempDir;

const CHANNEL: &[u8] = b"channel-0000-0001";

struct Device {
    _dir: TempDir,
    path: std::path::PathBuf,
    key: [u8; 32],
    session: Session,
}

impl Device {
    fn new(user: &str, device: &str, key_byte: u8) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        let key = [key_byte; 32];
        let mut session = Session::open(&path, &key).unwrap();
        session.create_identity(user, device).unwrap();
        Self {
            _dir: dir,
            path,
            key,
            session,
        }
    }

    fn blank(key_byte: u8) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        let key = [key_byte; 32];
        let session = Session::open(&path, &key).unwrap();
        Self {
            _dir: dir,
            path,
            key,
            session,
        }
    }

    fn reopen(&mut self) {
        // Drop the old session first so both connections close before the new ones open.
        let placeholder = Session::open(&self._dir.path().join("placeholder.db"), &[0; 32]).unwrap();
        drop(std::mem::replace(&mut self.session, placeholder));
        self.session = Session::open(&self.path, &self.key).unwrap();
    }

    fn key_package(&self) -> Vec<u8> {
        let package = self.session.generate_key_packages(1, false).unwrap().remove(0);
        // An MLSMessage: version mls10, wire format key_package — what the delivery service checks.
        assert_eq!(&package[..4], &[0, 1, 0, 5]);
        package
    }
}

/// Alice creates the channel's group and adds Bob, the way a first member invites a second.
fn alice_and_bob() -> (Device, Device) {
    let alice = Device::new("alice", "alice-laptop", 1);
    let bob = Device::new("bob", "bob-phone", 2);

    alice.session.create_group(CHANNEL).unwrap();
    let pending = alice.session.add_members(CHANNEL, &[bob.key_package()]).unwrap();
    assert_eq!(
        alice.session.merge_pending_commit(CHANNEL).unwrap(),
        pending.epoch_after
    );
    assert_eq!(
        bob.session.join_from_welcome(&pending.welcome.unwrap()).unwrap(),
        CHANNEL
    );
    (alice, bob)
}

fn send(from: &Device, id: &str, text: &str) -> Vec<u8> {
    let ciphertext = from.session.encrypt(CHANNEL, text.as_bytes()).unwrap();
    from.session.remember_sent(CHANNEL, id, 0, text.as_bytes()).unwrap();
    ciphertext
}

fn receive(to: &Device, id: &str, ciphertext: &[u8]) -> String {
    let message = to
        .session
        .receive_message(id, 0, ciphertext)
        .unwrap()
        .expect("an application message");
    String::from_utf8(message.payload).unwrap()
}

#[test]
fn two_devices_exchange_messages() {
    let (alice, bob) = alice_and_bob();

    let hello = send(&alice, "m1", "hello bob");
    assert!(
        !hello.windows(9).any(|w| w == b"hello bob"),
        "ciphertext must not contain the plaintext"
    );
    assert_eq!(receive(&bob, "m1", &hello), "hello bob");

    let reply = send(&bob, "m2", "hi alice");
    assert_eq!(receive(&alice, "m2", &reply), "hi alice");

    let members = alice.session.members(CHANNEL).unwrap();
    let mut who: Vec<_> = members
        .iter()
        .map(|m| (m.user_id.as_str(), m.device_id.as_str()))
        .collect();
    who.sort();
    assert_eq!(who, [("alice", "alice-laptop"), ("bob", "bob-phone")]);
}

#[test]
fn a_message_is_decrypted_once_then_served_from_the_cache() {
    let (alice, bob) = alice_and_bob();
    let hello = send(&alice, "m1", "only once");

    assert_eq!(receive(&bob, "m1", &hello), "only once");
    // Fetched again from history: MLS would refuse to decrypt it twice, the cache answers instead.
    assert_eq!(receive(&bob, "m1", &hello), "only once");
    let cached = bob.session.store().messages(CHANNEL, None, 10).unwrap();
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[0].sender_user_id, "alice");
    assert_eq!(cached[0].sender_device_id, "alice-laptop");
}

#[test]
fn state_and_plaintext_survive_a_restart() {
    let (alice, mut bob) = alice_and_bob();
    let first = send(&alice, "m1", "before restart");
    assert_eq!(receive(&bob, "m1", &first), "before restart");

    bob.reopen();
    assert_eq!(bob.session.device().unwrap().device_id, "bob-phone");
    assert_eq!(
        bob.session.store().message(CHANNEL, "m1").unwrap().unwrap().payload,
        b"before restart"
    );

    let second = send(&alice, "m2", "after restart");
    assert_eq!(receive(&bob, "m2", &second), "after restart");
}

#[test]
fn every_member_derives_the_same_media_key_and_it_rotates() {
    let (alice, bob) = alice_and_bob();
    let key = |d: &Device| {
        d.session
            .export_secret(CHANNEL, "raindrop/voice/v1", CHANNEL, 32)
            .unwrap()
    };

    let before = key(&alice);
    assert_eq!(before, key(&bob));

    let update = bob.session.self_update(CHANNEL).unwrap();
    bob.session.merge_pending_commit(CHANNEL).unwrap();
    let (_, incoming) = alice.session.process(&update.commit).unwrap();
    assert!(matches!(incoming, Incoming::Commit { .. }));

    let after = key(&alice);
    assert_eq!(after, key(&bob));
    assert_ne!(before, after);
}

#[test]
fn a_device_joins_by_itself_from_the_published_group_info() {
    let (alice, bob) = alice_and_bob();
    let carol = Device::new("carol", "carol-desktop", 3);

    let group_info = alice.session.group_info(CHANNEL).unwrap();
    let (group_id, pending) = carol
        .session
        .join_by_external_commit(CHANNEL, &group_info)
        .unwrap();
    assert_eq!(group_id, CHANNEL);
    // The join is merged already: the pending commit names the epoch carol is at, and merging it
    // changes nothing.
    assert_eq!(pending.epoch_after, carol.session.epoch(CHANNEL).unwrap());
    assert_eq!(
        carol.session.merge_pending_commit(CHANNEL).unwrap(),
        pending.epoch_after
    );

    for existing in [&alice, &bob] {
        let (_, incoming) = existing.session.process(&pending.commit).unwrap();
        assert!(matches!(incoming, Incoming::Commit { .. }));
    }

    let hello = send(&carol, "m1", "hi all");
    assert_eq!(receive(&alice, "m1", &hello), "hi all");
    assert_eq!(receive(&bob, "m1", &hello), "hi all");
    assert_eq!(alice.session.members(CHANNEL).unwrap().len(), 3);
    // The commit moved everybody to the epoch the joiner reported.
    assert_eq!(alice.session.epoch(CHANNEL).unwrap(), pending.epoch_after);
    assert_eq!(bob.session.epoch(CHANNEL).unwrap(), pending.epoch_after);
}

#[test]
fn an_external_join_that_fails_validation_leaves_no_group_behind() {
    let (alice, _bob) = alice_and_bob();
    let carol = Device::new("carol", "carol-desktop", 3);
    // Carol already pinned a different identity key for Bob, so Bob's device in the group is refused.
    carol
        .session
        .store()
        .pin_identity("bob", &[7; 32], 0)
        .unwrap();

    let group_info = alice.session.group_info(CHANNEL).unwrap();
    let result = carol.session.join_by_external_commit(CHANNEL, &group_info);
    assert!(matches!(result, Err(CryptoError::IdentityChanged { ref user_id, .. }) if user_id == "bob"));
    assert!(
        !carol.session.has_group(CHANNEL).unwrap(),
        "an unvalidated group must not stay in storage"
    );
    assert!(carol.session.epoch(CHANNEL).is_err());
}

#[test]
fn an_external_join_refuses_a_group_info_for_another_group() {
    let (alice, _bob) = alice_and_bob();
    let carol = Device::new("carol", "carol-desktop", 3);

    let group_info = alice.session.group_info(CHANNEL).unwrap();
    let other: &[u8] = b"channel-0000-0002";
    let result = carol.session.join_by_external_commit(other, &group_info);
    assert!(matches!(result, Err(CryptoError::Verification(_))));
    assert!(!carol.session.has_group(CHANNEL).unwrap());
    assert!(!carol.session.has_group(other).unwrap());
}

#[test]
fn an_external_join_never_replaces_a_group_the_device_holds() {
    let (alice, bob) = alice_and_bob();
    let epoch = bob.session.epoch(CHANNEL).unwrap();

    // Bob holds the group already; a group info for it must not overwrite his copy.
    let group_info = alice.session.group_info(CHANNEL).unwrap();
    let result = bob.session.join_by_external_commit(CHANNEL, &group_info);
    assert!(matches!(result, Err(CryptoError::Store(_))));
    assert_eq!(bob.session.epoch(CHANNEL).unwrap(), epoch);
    assert!(bob.session.has_group(CHANNEL).unwrap());
}

#[test]
fn a_removed_device_cannot_read_what_follows() {
    let (alice, bob) = alice_and_bob();
    let bob_leaf = alice
        .session
        .members(CHANNEL)
        .unwrap()
        .into_iter()
        .find(|m| m.user_id == "bob")
        .unwrap()
        .leaf_index;

    let removal = alice.session.remove_members(CHANNEL, &[bob_leaf]).unwrap();
    alice.session.merge_pending_commit(CHANNEL).unwrap();

    let (_, incoming) = bob.session.process(&removal.commit).unwrap();
    assert!(matches!(incoming, Incoming::Commit { removed_self: true, .. }));

    let secret = send(&alice, "m1", "bob is gone");
    assert!(bob.session.receive_message("m1", 0, &secret).is_err());
}

#[test]
fn an_impostor_with_a_different_identity_key_is_refused() {
    let (alice, _bob) = alice_and_bob();

    // Somebody (a malicious server, say) mints a device claiming to be Bob, but cannot sign it with
    // Bob's real identity key. Alice pinned Bob's key when he joined, so she refuses it.
    let impostor = Device::new("bob", "bob-new-phone", 9);
    let result = alice.session.add_members(CHANNEL, &[impostor.key_package()]);
    assert!(matches!(result, Err(CryptoError::IdentityChanged { ref user_id, .. }) if user_id == "bob"));
}

/// Alice and Bob in a group, with Alice's pin for Bob no longer matching the identity key his device
/// carries (a restored backup put an older key for him back, say). Returns Bob's real key.
fn alice_with_a_stale_pin_for_bob() -> (Device, Device, Vec<u8>) {
    let (alice, bob) = alice_and_bob();
    let bob_key = bob.session.device().unwrap().user_identity_key.clone();
    alice.session.store().replace_identity("bob", &[9; 32], 0).unwrap();
    (alice, bob, bob_key)
}

fn is_bob_changed<T>(result: &raindrop_crypto::Result<T>) -> bool {
    matches!(result, Err(CryptoError::IdentityChanged { user_id, .. }) if user_id == "bob")
}

#[test]
fn a_message_from_a_changed_identity_is_held_until_the_key_is_accepted() {
    let (alice, bob, bob_key) = alice_with_a_stale_pin_for_bob();
    let message = send(&bob, "m1", "after the reinstall");

    // MLS decrypts it (spending its key) before the pin refuses the sender.
    assert!(is_bob_changed(&alice.session.receive_message("m1", 0, &message)));
    assert!(alice.session.store().messages(CHANNEL, None, 10).unwrap().is_empty());
    let held = alice.session.store().held_messages(CHANNEL).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].message.payload, b"after the reinstall");
    assert_eq!(held[0].message.sender_device_id, "bob-phone");
    assert_eq!(held[0].sender_identity_key, bob_key);
    // Asked for again, it is still a trust decision, not an undecryptable message.
    assert!(is_bob_changed(&alice.session.receive_message("m1", 0, &message)));

    assert_eq!(alice.session.accept_changed_identity("bob", &bob_key).unwrap(), 1);
    let cached = alice.session.store().messages(CHANNEL, None, 10).unwrap();
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[0].message_id, "m1");
    assert_eq!(cached[0].payload, b"after the reinstall");
    assert!(alice.session.store().held_messages(CHANNEL).unwrap().is_empty());
    assert_eq!(receive(&alice, "m1", &message), "after the reinstall");
    // And Bob's next message is an ordinary one.
    let next = send(&bob, "m2", "trusted again");
    assert_eq!(receive(&alice, "m2", &next), "trusted again");
}

#[test]
fn a_held_message_stays_held_while_the_change_is_not_accepted() {
    let (mut alice, bob, _) = alice_with_a_stale_pin_for_bob();
    let message = send(&bob, "m1", "not accepted");
    assert!(is_bob_changed(&alice.session.receive_message("m1", 0, &message)));

    // Accepting some other key for Bob releases nothing held under his real one.
    assert_eq!(alice.session.accept_changed_identity("bob", &[8; 32]).unwrap(), 0);
    alice.reopen();
    assert!(alice.session.store().messages(CHANNEL, None, 10).unwrap().is_empty());
    assert_eq!(alice.session.store().held_messages(CHANNEL).unwrap().len(), 1);
    assert!(is_bob_changed(&alice.session.receive_message("m1", 0, &message)));
}

#[test]
fn deleting_a_group_clears_its_held_messages() {
    let (alice, bob, _) = alice_with_a_stale_pin_for_bob();
    let message = send(&bob, "m1", "held then deleted");
    assert!(is_bob_changed(&alice.session.receive_message("m1", 0, &message)));

    alice.session.delete_group(CHANNEL).unwrap();
    assert!(alice.session.store().held_messages(CHANNEL).unwrap().is_empty());
}

#[test]
fn deleting_a_group_clears_its_cached_messages() {
    let (alice, bob) = alice_and_bob();
    let message = send(&bob, "m1", "cached then deleted");
    assert_eq!(receive(&alice, "m1", &message), "cached then deleted");
    send(&alice, "m2", "sent then deleted");
    assert_eq!(alice.session.store().messages(CHANNEL, None, 10).unwrap().len(), 2);

    alice.session.delete_group(CHANNEL).unwrap();
    assert!(!alice.session.has_group(CHANNEL).unwrap());
    assert!(alice.session.store().messages(CHANNEL, None, 10).unwrap().is_empty());
}

#[test]
fn resetting_a_group_keeps_its_held_messages() {
    let (alice, bob, bob_key) = alice_with_a_stale_pin_for_bob();
    let message = send(&bob, "m1", "held then reset");
    assert!(is_bob_changed(&alice.session.receive_message("m1", 0, &message)));

    alice.session.reset_group(CHANNEL).unwrap();
    assert!(!alice.session.has_group(CHANNEL).unwrap());
    let held = alice.session.store().held_messages(CHANNEL).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].message.payload, b"held then reset");
    // Still a trust decision, and accepting the key releases it into the cache.
    assert!(is_bob_changed(&alice.session.receive_message("m1", 0, &message)));
    assert_eq!(alice.session.accept_changed_identity("bob", &bob_key).unwrap(), 1);
    assert_eq!(alice.session.store().messages(CHANNEL, None, 10).unwrap().len(), 1);
}

#[test]
fn resetting_a_group_that_is_not_held_does_nothing() {
    let alice = Device::new("alice", "alice-laptop", 1);
    alice.session.reset_group(CHANNEL).unwrap();
    alice.session.create_group(CHANNEL).unwrap();
    alice.session.reset_group(CHANNEL).unwrap();
    alice.session.reset_group(CHANNEL).unwrap();
    assert!(!alice.session.has_group(CHANNEL).unwrap());
}

#[test]
fn a_resync_resets_the_group_and_the_rejoin_keeps_the_history() {
    let (alice, bob) = alice_and_bob();
    let m1 = send(&bob, "m1", "before the resync");
    assert_eq!(receive(&alice, "m1", &m1), "before the resync");
    send(&alice, "m2", "alice's own");

    // The server stores P1 but answers with an error, so Alice discards it; Bob follows P1, and
    // P1's echo is something Alice cannot follow.
    let p1 = alice.session.self_update(CHANNEL).unwrap();
    alice.session.discard_pending_commit(CHANNEL).unwrap();
    bob.session.process(&p1.commit).unwrap();
    assert!(matches!(
        alice.session.process(&p1.commit),
        Err(CryptoError::ResyncRequired)
    ));

    // Resetting drops the MLS state and nothing else.
    alice.session.reset_group(CHANNEL).unwrap();
    assert!(!alice.session.has_group(CHANNEL).unwrap());
    let cached = alice.session.store().messages(CHANNEL, None, 10).unwrap();
    assert_eq!(cached.len(), 2);
    assert!(cached.iter().any(|m| m.message_id == "m1" && m.payload == b"before the resync"));
    assert!(cached.iter().any(|m| m.message_id == "m2" && m.payload == b"alice's own"));

    // Rejoin by external commit from the group's current state.
    let group_info = bob.session.group_info(CHANNEL).unwrap();
    let (_, rejoin) = alice
        .session
        .join_by_external_commit(CHANNEL, &group_info)
        .unwrap();
    assert_eq!(alice.session.merge_pending_commit(CHANNEL).unwrap(), rejoin.epoch_after);
    bob.session.process(&rejoin.commit).unwrap();

    // The same message ids reappear (the history is paged again): they come from the cache, MLS
    // is not asked to decrypt them a second time, and nothing is duplicated.
    assert_eq!(receive(&alice, "m1", &m1), "before the resync");
    assert_eq!(alice.session.store().messages(CHANNEL, None, 10).unwrap().len(), 2);

    // And the rejoined group works both ways.
    let m3 = send(&bob, "m3", "after the rejoin");
    assert_eq!(receive(&alice, "m3", &m3), "after the rejoin");
    let m4 = send(&alice, "m4", "and back");
    assert_eq!(receive(&bob, "m4", &m4), "and back");
    assert_eq!(alice.session.store().messages(CHANNEL, None, 10).unwrap().len(), 4);
}

#[test]
fn a_commit_from_a_changed_identity_takes_the_device_out_of_the_group() {
    let (alice, bob) = alice_and_bob();
    let hello = send(&bob, "m1", "before the change");
    assert_eq!(receive(&alice, "m1", &hello), "before the change");
    let bob_key = bob.session.device().unwrap().user_identity_key.clone();
    alice.session.store().replace_identity("bob", &[9; 32], 0).unwrap();

    // A commit of Alice's own is pending when Bob's arrives.
    alice.session.self_update(CHANNEL).unwrap();
    let pending_key = format!(
        "pending_commit.{}",
        CHANNEL.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    assert!(alice.session.store().get_meta(&pending_key).unwrap().is_some());

    let update = bob.session.self_update(CHANNEL).unwrap();
    bob.session.merge_pending_commit(CHANNEL).unwrap();

    // Refusing the commit is leaving the group: it could never be processed again.
    assert!(is_bob_changed(&alice.session.process(&update.commit)));
    assert!(!alice.session.has_group(CHANNEL).unwrap());
    assert!(alice.session.store().get_meta(&pending_key).unwrap().is_none());
    // What she had already read is kept.
    assert_eq!(alice.session.store().messages(CHANNEL, None, 10).unwrap().len(), 1);

    // Until she accepts, rejoining refuses the same member again and keeps nothing.
    let group_info = bob.session.group_info(CHANNEL).unwrap();
    assert!(is_bob_changed(&alice.session.join_by_external_commit(CHANNEL, &group_info)));
    assert!(!alice.session.has_group(CHANNEL).unwrap());

    alice.session.accept_changed_identity("bob", &bob_key).unwrap();
    let (_, rejoin) = alice.session.join_by_external_commit(CHANNEL, &group_info).unwrap();
    alice.session.merge_pending_commit(CHANNEL).unwrap();
    bob.session.process(&rejoin.commit).unwrap();
    let hello = send(&bob, "m2", "welcome back");
    assert_eq!(receive(&alice, "m2", &hello), "welcome back");
}

#[test]
fn the_refusal_carries_the_key_that_was_presented_and_the_one_pinned() {
    let (alice, bob, bob_key) = alice_with_a_stale_pin_for_bob();
    let message = send(&bob, "m1", "who is this");

    // The first time, and every time after it, from the held copy.
    for _ in 0..2 {
        match alice.session.receive_message("m1", 0, &message) {
            Err(CryptoError::IdentityChanged {
                user_id,
                pinned_key,
                presented_key,
            }) => {
                assert_eq!(user_id, "bob");
                assert_eq!(pinned_key, vec![9; 32]);
                assert_eq!(presented_key, bob_key);
            }
            other => panic!("expected IdentityChanged, got {other:?}"),
        }
    }

    // A refused key package says the same.
    let impostor = Device::new("bob", "bob-new-phone", 9);
    let impostor_key = impostor.session.device().unwrap().user_identity_key.clone();
    match alice.session.add_members(CHANNEL, &[impostor.key_package()]) {
        Err(CryptoError::IdentityChanged {
            pinned_key,
            presented_key,
            ..
        }) => {
            assert_eq!(pinned_key, vec![9; 32]);
            assert_eq!(presented_key, impostor_key);
        }
        other => panic!("expected IdentityChanged, got {other:?}"),
    }
}

#[test]
fn accepting_the_presented_key_from_the_refusal_releases_the_held_message() {
    let (alice, bob, bob_key) = alice_with_a_stale_pin_for_bob();
    let message = send(&bob, "m1", "after the reinstall");

    let Err(CryptoError::IdentityChanged {
        user_id,
        presented_key,
        ..
    }) = alice.session.receive_message("m1", 0, &message)
    else {
        panic!("expected IdentityChanged");
    };
    assert_eq!(presented_key, bob_key);

    assert_eq!(alice.session.accept_changed_identity(&user_id, &presented_key).unwrap(), 1);
    assert_eq!(receive(&alice, "m1", &message), "after the reinstall");
    assert_eq!(alice.session.store().pinned_identity("bob").unwrap().unwrap().identity_key, bob_key);
}

#[test]
fn no_identity_change_is_pending_until_one_is_met() {
    let (alice, bob) = alice_and_bob();
    assert!(alice.session.pending_identity_changes().unwrap().is_empty());
    let message = send(&bob, "m1", "all is well");
    assert_eq!(receive(&alice, "m1", &message), "all is well");
    assert!(alice.session.pending_identity_changes().unwrap().is_empty());
}

#[test]
fn pending_identity_changes_list_held_messages_and_left_groups_across_a_restart() {
    let (mut alice, bob, bob_key) = alice_with_a_stale_pin_for_bob();
    let m1 = send(&bob, "m1", "one");
    let m2 = send(&bob, "m2", "two");
    assert!(is_bob_changed(&alice.session.receive_message("m1", 0, &m1)));
    assert!(is_bob_changed(&alice.session.receive_message("m2", 0, &m2)));

    // Held messages alone: one entry, nothing left yet.
    let pending = alice.session.pending_identity_changes().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].user_id, "bob");
    assert_eq!(pending[0].pinned_key.as_deref(), Some(&[9u8; 32][..]));
    assert_eq!(pending[0].presented_key, bob_key);
    assert_eq!(pending[0].held_messages, 2);
    assert_eq!(pending[0].held_group_ids, vec![CHANNEL.to_vec()]);
    assert!(pending[0].left_group_ids.is_empty());

    // Bob's commit is refused, which takes Alice out of the group.
    let update = bob.session.self_update(CHANNEL).unwrap();
    bob.session.merge_pending_commit(CHANNEL).unwrap();
    assert!(is_bob_changed(&alice.session.process(&update.commit)));
    assert!(!alice.session.has_group(CHANNEL).unwrap());

    // All of it is in the encrypted store, so it is the same after a restart.
    let before = alice.session.pending_identity_changes().unwrap();
    alice.reopen();
    let after = alice.session.pending_identity_changes().unwrap();
    assert_eq!(before, after);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].held_messages, 2);
    assert_eq!(after[0].left_group_ids, vec![CHANNEL.to_vec()]);

    // Accepting some other key changes none of it.
    alice.session.accept_changed_identity("bob", &[8; 32]).unwrap();
    assert_eq!(alice.session.pending_identity_changes().unwrap().len(), 1);
    alice.session.store().replace_identity("bob", &[9; 32], 0).unwrap();

    // Accepting the presented key clears it, and the left group is Alice's to join again.
    assert_eq!(alice.session.accept_changed_identity("bob", &bob_key).unwrap(), 2);
    assert!(alice.session.pending_identity_changes().unwrap().is_empty());
    alice.reopen();
    assert!(alice.session.pending_identity_changes().unwrap().is_empty());
    let group_info = bob.session.group_info(CHANNEL).unwrap();
    let (_, rejoin) = alice.session.join_by_external_commit(CHANNEL, &group_info).unwrap();
    alice.session.merge_pending_commit(CHANNEL).unwrap();
    bob.session.process(&rejoin.commit).unwrap();
    assert_eq!(receive(&alice, "m1", &m1), "one");
}

#[test]
fn a_refused_join_is_pending_until_accepted_joined_or_deleted() {
    let (alice, bob) = alice_and_bob();
    let carol = Device::new("carol", "carol-desktop", 3);
    let bob_key = bob.session.device().unwrap().user_identity_key.clone();
    carol.session.store().pin_identity("bob", &[7; 32], 0).unwrap();

    let group_info = alice.session.group_info(CHANNEL).unwrap();
    assert!(is_bob_changed(&carol.session.join_by_external_commit(CHANNEL, &group_info)));
    let pending = carol.session.pending_identity_changes().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].pinned_key.as_deref(), Some(&[7u8; 32][..]));
    assert_eq!(pending[0].presented_key, bob_key);
    assert_eq!(pending[0].held_messages, 0);
    assert_eq!(pending[0].left_group_ids, vec![CHANNEL.to_vec()]);

    // Deleting the group forgets it.
    carol.session.delete_group(CHANNEL).unwrap();
    assert!(carol.session.pending_identity_changes().unwrap().is_empty());

    // Joining it, once accepted, leaves nothing behind either.
    assert!(is_bob_changed(&carol.session.join_by_external_commit(CHANNEL, &group_info)));
    carol.session.accept_changed_identity("bob", &bob_key).unwrap();
    assert!(carol.session.pending_identity_changes().unwrap().is_empty());
    carol.session.join_by_external_commit(CHANNEL, &group_info).unwrap();
    assert!(carol.session.pending_identity_changes().unwrap().is_empty());
}

#[test]
fn a_standalone_external_add_proposal_is_refused_and_never_committed() {
    use openmls::prelude::{
        BasicCredential, CredentialWithKey, GroupEpoch, GroupId, JoinProposal, KeyPackage, OpenMlsProvider,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use raindrop_crypto::CIPHERSUITE;
    use raindrop_crypto::identity::UserIdentity;

    let (alice, _bob) = alice_and_bob();

    // A malicious server mints "Bob" under an identity key of its own and asks to be added by an
    // external join proposal (accepted from a non-member). Had Alice stored it, her next commit would
    // have swept it in without its certificate ever being checked.
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
    let certificate = UserIdentity::generate().certify_device("bob", "bob-mallory", signer.public(), 0).unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(certificate.to_bytes().unwrap()).into(),
        signature_key: signer.public().into(),
    };
    let bundle = KeyPackage::builder()
        .build(CIPHERSUITE, &provider, &signer, credential)
        .unwrap();
    let proposal = JoinProposal::new::<<OpenMlsRustCrypto as OpenMlsProvider>::StorageProvider>(
        bundle.key_package().clone(),
        GroupId::from_slice(CHANNEL),
        GroupEpoch::from(alice.session.epoch(CHANNEL).unwrap()),
        &signer,
    )
    .unwrap()
    .to_bytes()
    .unwrap();

    assert!(matches!(
        alice.session.process(&proposal),
        Err(CryptoError::Verification(_))
    ));

    alice.session.self_update(CHANNEL).unwrap();
    alice.session.merge_pending_commit(CHANNEL).unwrap();
    assert_eq!(alice.session.members(CHANNEL).unwrap().len(), 2);
}

#[test]
fn only_one_of_two_racing_commits_wins() {
    let (alice, bob) = alice_and_bob();

    let from_alice = alice.session.self_update(CHANNEL).unwrap();
    let _from_bob = bob.session.self_update(CHANNEL).unwrap();

    // The server orders commits per epoch and takes Alice's. It echoes her commit back to her, and
    // tells Bob his lost.
    let (_, echoed) = alice.session.process(&from_alice.commit).unwrap();
    assert!(matches!(echoed, Incoming::Commit { .. }));
    bob.session.discard_pending_commit(CHANNEL).unwrap();
    bob.session.process(&from_alice.commit).unwrap();

    assert_eq!(
        alice.session.epoch(CHANNEL).unwrap(),
        bob.session.epoch(CHANNEL).unwrap()
    );
    let hello = send(&bob, "m1", "still in sync");
    assert_eq!(receive(&alice, "m1", &hello), "still in sync");
}

#[test]
fn a_winning_commit_replaces_a_pending_one_whose_fate_was_unknown() {
    // Alice's commit timed out: the client kept it pending without discarding it. Bob's won the epoch.
    let (alice, bob) = alice_and_bob();
    let before = alice.session.epoch(CHANNEL).unwrap();
    let _unknown = alice.session.self_update(CHANNEL).unwrap();
    let winner = bob.session.self_update(CHANNEL).unwrap();
    bob.session.merge_pending_commit(CHANNEL).unwrap();

    // Processing the winner with her own still pending moves her on and drops the pending one.
    let (_, incoming) = alice.session.process(&winner.commit).unwrap();
    assert!(matches!(incoming, Incoming::Commit { epoch, .. } if epoch == winner.epoch_after));
    assert_eq!(alice.session.epoch(CHANNEL).unwrap(), before + 1);
    // Nothing is left pending (this is a no-op, not an error) and the group works.
    alice.session.discard_pending_commit(CHANNEL).unwrap();
    let hello = send(&bob, "m1", "still in sync");
    assert_eq!(receive(&alice, "m1", &hello), "still in sync");

    // A commit the server never saw is simply discarded once a sync proves it, and the group goes on.
    let _never_seen = alice.session.self_update(CHANNEL).unwrap();
    alice.session.discard_pending_commit(CHANNEL).unwrap();
    assert_eq!(alice.session.epoch(CHANNEL).unwrap(), before + 1);
    let next = alice.session.self_update(CHANNEL).unwrap();
    let (_, echoed) = alice.session.process(&next.commit).unwrap();
    assert!(matches!(echoed, Incoming::Commit { epoch, .. } if epoch == next.epoch_after));
}

#[test]
fn an_own_commit_this_device_discarded_is_a_resync_not_a_silent_fork() {
    let (alice, bob) = alice_and_bob();
    let before = alice.session.epoch(CHANNEL).unwrap();

    // The server stores P1 but answers with an error, so Alice discards it. Bob follows P1.
    let p1 = alice.session.self_update(CHANNEL).unwrap();
    alice.session.discard_pending_commit(CHANNEL).unwrap();
    bob.session.process(&p1.commit).unwrap();

    // P1's echo reaches Alice. She cannot follow it, and must hear so rather than stay behind.
    assert!(matches!(
        alice.session.process(&p1.commit),
        Err(CryptoError::ResyncRequired)
    ));
    assert_eq!(alice.session.epoch(CHANNEL).unwrap(), before);

    // With a different commit of hers pending, P1 is still not hers to merge: P2 is not merged in
    // its place, and stays pending.
    let p2 = alice.session.self_update(CHANNEL).unwrap();
    assert!(matches!(
        alice.session.process(&p1.commit),
        Err(CryptoError::ResyncRequired)
    ));
    assert_eq!(alice.session.epoch(CHANNEL).unwrap(), before);
    let (_, echoed) = alice.session.process(&p2.commit).unwrap();
    assert!(matches!(echoed, Incoming::Commit { epoch, .. } if epoch == p2.epoch_after));
}

#[test]
fn the_echo_of_each_kind_of_pending_commit_still_merges() {
    let (alice, _bob) = alice_and_bob();
    let carol = Device::new("carol", "carol-pc", 3);

    let added = alice.session.add_members(CHANNEL, &[carol.key_package()]).unwrap();
    let (_, echoed) = alice.session.process(&added.commit).unwrap();
    assert!(matches!(echoed, Incoming::Commit { epoch, .. } if epoch == added.epoch_after));

    let members = alice.session.members(CHANNEL).unwrap();
    let leaf = members.iter().find(|m| m.user_id == "carol").unwrap().leaf_index;
    let removed = alice.session.remove_members(CHANNEL, &[leaf]).unwrap();
    let (_, echoed) = alice.session.process(&removed.commit).unwrap();
    assert!(matches!(echoed, Incoming::Commit { epoch, .. } if epoch == removed.epoch_after));
    assert_eq!(alice.session.members(CHANNEL).unwrap().len(), 2);
}

#[test]
fn a_backup_restores_the_identity_onto_a_new_device() {
    let (alice, bob) = alice_and_bob();
    let before = safety_number(
        "alice",
        &alice.session.device().unwrap().user_identity_key,
        "bob",
        &bob.session.device().unwrap().user_identity_key,
    );

    let recovery = RecoveryKey::generate();
    let blob = backup::seal_with_recovery_key(&alice.session.backup_contents().unwrap(), &recovery).unwrap();

    // Every device lost; Alice types her 24 words into a fresh install.
    let mut replacement = Device::blank(5);
    let contents =
        backup::open_with_recovery_key(&blob, &RecoveryKey::from_words(&recovery.to_words()).unwrap()).unwrap();
    let restored = replacement
        .session
        .restore_identity(&contents, "alice-new-laptop")
        .unwrap();

    assert_eq!(
        restored.user_identity_key,
        alice.session.device().unwrap().user_identity_key
    );
    assert_ne!(
        restored.device_signature_key,
        alice.session.device().unwrap().device_signature_key
    );
    assert!(
        replacement.session.store().pinned_identity("bob").unwrap().is_some(),
        "pins survive the restore"
    );

    let after = safety_number(
        "alice",
        &restored.user_identity_key,
        "bob",
        &bob.session.device().unwrap().user_identity_key,
    );
    assert_eq!(before, after);

    // The restored device is accepted by Bob as Alice, because it carries her real identity key.
    let group_info = bob.session.group_info(CHANNEL).unwrap();
    let (_, pending) = replacement
        .session
        .join_by_external_commit(CHANNEL, &group_info)
        .unwrap();
    replacement.session.merge_pending_commit(CHANNEL).unwrap();
    bob.session.process(&pending.commit).unwrap();

    let _ = &mut replacement;
    let hello = send(&bob, "m1", "welcome back");
    assert_eq!(receive(&replacement, "m1", &hello), "welcome back");
}

#[test]
fn a_new_device_is_linked_from_an_existing_one() {
    let (alice, bob) = alice_and_bob();
    let mut phone = Device::blank(11);

    let (offer, commitment, code_secret) = phone.session.begin_device_link("alice", "alice-phone").unwrap();
    let approval = alice
        .session
        .approve_device_link(&offer, &commitment, code_secret.as_slice())
        .unwrap();
    let linked = phone.session.complete_device_link(&approval).unwrap();

    assert_eq!(linked.user_id, "alice");
    assert_eq!(linked.device_id, "alice-phone");
    assert_eq!(
        linked.user_identity_key,
        alice.session.device().unwrap().user_identity_key
    );
    assert!(
        phone.session.store().pinned_identity("bob").unwrap().is_some(),
        "pins travel with the link"
    );

    // Bob accepts the phone as Alice: its certificate carries her real identity key.
    let commit = bob.session.add_members(CHANNEL, &[phone.key_package()]).unwrap();
    bob.session.merge_pending_commit(CHANNEL).unwrap();
    alice.session.process(&commit.commit).unwrap();
    phone.session.join_from_welcome(&commit.welcome.unwrap()).unwrap();
    let hello = send(&bob, "m1", "hi phone");
    assert_eq!(receive(&phone, "m1", &hello), "hi phone");

    let _ = &mut phone;
}

#[test]
fn a_link_offer_that_does_not_match_its_code_is_refused() {
    let (alice, _bob) = alice_and_bob();
    let mut phone = Device::blank(12);
    let mut attacker = Device::blank(13);

    let (_, commitment, code_secret) = phone.session.begin_device_link("alice", "alice-phone").unwrap();
    // The server swaps in an offer of its own; the code the user carried does not match it.
    let (substituted, _, _) = attacker.session.begin_device_link("alice", "alice-phone").unwrap();
    assert!(matches!(
        alice
            .session
            .approve_device_link(&substituted, &commitment, code_secret.as_slice()),
        Err(CryptoError::Verification(_))
    ));

    // An offer for a different user is refused even with a matching code.
    let (for_bob, bob_code, bob_secret) = attacker.session.begin_device_link("bob", "x").unwrap();
    assert!(
        alice
            .session
            .approve_device_link(&for_bob, &bob_code, bob_secret.as_slice())
            .is_err()
    );

    let _ = (&mut phone, &mut attacker);
}

#[test]
fn a_link_approval_sealed_by_the_server_is_refused() {
    let (alice, _bob) = alice_and_bob();
    let mut phone = Device::blank(14);
    // The server has an identity of its own, made out to the same user, and the phone's offer, from
    // which it can compute the commitment. It never sees the code secret in the link code.
    let server = Device::new("alice", "server-made", 15);

    let (offer, commitment, code_secret) = phone.session.begin_device_link("alice", "alice-phone").unwrap();
    let forged = server
        .session
        .approve_device_link(&offer, &commitment, &[0u8; 16])
        .unwrap();
    assert!(matches!(
        phone.session.complete_device_link(&forged),
        Err(CryptoError::Verification(_))
    ));
    assert!(phone.session.device().is_none(), "nothing is installed from a forged approval");

    // The link is still in progress, and the real approval completes it.
    let approval = alice
        .session
        .approve_device_link(&offer, &commitment, code_secret.as_slice())
        .unwrap();
    let linked = phone.session.complete_device_link(&approval).unwrap();
    assert_eq!(
        linked.user_identity_key,
        alice.session.device().unwrap().user_identity_key
    );
}

#[test]
fn the_session_challenge_signature_is_plain_ed25519_by_the_device_key() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let alice = Device::new("alice", "alice-laptop", 14);
    let nonce = [42u8; 32];
    let signature = alice.session.sign_session_challenge(&nonce).unwrap();

    let key: [u8; 32] = alice
        .session
        .device()
        .unwrap()
        .device_signature_key
        .as_slice()
        .try_into()
        .unwrap();
    let mut signed = b"raindrop/session-binding/v1\n".to_vec();
    signed.extend_from_slice(&nonce);
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify(&signed, &Signature::from_slice(&signature).unwrap())
        .expect("the server verifies exactly this");
}

#[test]
fn a_message_attestation_is_ed25519_by_the_device_key_over_its_context() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let alice = Device::new("alice", "alice-laptop", 15);
    let signature = alice.session.sign_message_attestation(b"canonical").unwrap();
    let key: [u8; 32] = alice
        .session
        .device()
        .unwrap()
        .device_signature_key
        .as_slice()
        .try_into()
        .unwrap();
    let key = VerifyingKey::from_bytes(&key).unwrap();
    let signature = Signature::from_slice(&signature).unwrap();

    key.verify(b"raindrop/message-attestation/v1\ncanonical", &signature)
        .expect("the server verifies exactly this");
    // Not interchangeable with a session-binding signature over the same bytes.
    assert!(
        key.verify(b"raindrop/session-binding/v1\ncanonical", &signature)
            .is_err()
    );

    // A message with files is signed under its own context, and neither version stands in for the other.
    let with_files = alice.session.sign_message_attestation_v2(b"canonical").unwrap();
    let with_files = Signature::from_slice(&with_files).unwrap();
    key.verify(b"raindrop/message-attestation/v2\ncanonical", &with_files)
        .expect("the server verifies exactly this");
    assert!(
        key.verify(b"raindrop/message-attestation/v1\ncanonical", &with_files)
            .is_err()
    );
}

// ── The root identity ────────────────────────────────────────────────────────────────────────────

const SERVER_KEY: [u8; 65] = [4; 65];

#[test]
fn two_devices_with_the_same_root_are_the_same_user_and_can_talk() {
    use raindrop_crypto::root::RootSecret;

    let root = RootSecret::generate();
    let mut phone = Device::blank(31);
    let mut laptop = Device::blank(32);
    let phone_identity = phone
        .session
        .create_identity_from_root(&root, &SERVER_KEY, "phone")
        .unwrap();
    // The laptop was paired: it holds the same root and nothing else from the phone.
    let laptop_identity = laptop
        .session
        .create_identity_from_root(&RootSecret::from_bytes(root.as_bytes()).unwrap(), &SERVER_KEY, "laptop")
        .unwrap();

    assert_eq!(phone_identity.user_id, laptop_identity.user_id);
    assert_eq!(phone_identity.user_identity_key, laptop_identity.user_identity_key);
    assert_ne!(phone_identity.device_signature_key, laptop_identity.device_signature_key);

    // Each certified itself, and the other accepts it as the same pinned user.
    phone.session.create_group(CHANNEL).unwrap();
    let pending = phone.session.add_members(CHANNEL, &[laptop.key_package()]).unwrap();
    phone.session.merge_pending_commit(CHANNEL).unwrap();
    laptop.session.join_from_welcome(&pending.welcome.unwrap()).unwrap();

    let ciphertext = phone.session.encrypt(CHANNEL, b"from the phone").unwrap();
    match laptop.session.process(&ciphertext).unwrap().1 {
        Incoming::Application { sender, payload, .. } => {
            assert_eq!(sender.device_id, "phone");
            assert_eq!(payload, b"from the phone");
        }
        other => panic!("expected a message, got {other:?}"),
    }
}

#[test]
fn a_reclaimed_account_keeps_its_id_and_the_roots_identity_key() {
    use raindrop_crypto::root::RootSecret;

    let root = RootSecret::generate();
    let mut phone = Device::blank(34);
    let mut laptop = Device::blank(35);
    let derived = phone
        .session
        .create_identity_from_root(&root, &SERVER_KEY, "phone")
        .unwrap();
    let reclaimed = laptop
        .session
        .create_identity_from_root_for(
            &RootSecret::from_bytes(root.as_bytes()).unwrap(),
            &SERVER_KEY,
            "0f8fad5b-d9cb-469f-a165-70867728950e",
            "laptop",
        )
        .unwrap();

    // The id is the one given; the identity key is the one every device of this root derives.
    assert_eq!(reclaimed.user_id, "0f8fad5b-d9cb-469f-a165-70867728950e");
    assert_ne!(reclaimed.user_id, derived.user_id);
    assert_eq!(reclaimed.user_identity_key, derived.user_identity_key);

    let mut empty = Device::blank(36);
    assert!(empty
        .session
        .create_identity_from_root_for(&root, &SERVER_KEY, "", "tablet")
        .is_err());
}

#[test]
fn a_sign_in_signature_is_bound_to_the_server_and_the_nonce() {
    use ed25519_dalek::{Signature, VerifyingKey};
    use raindrop_crypto::root::RootSecret;

    let mut device = Device::blank(33);
    let identity = device
        .session
        .create_identity_from_root(&RootSecret::generate(), &SERVER_KEY, "phone")
        .unwrap();
    let signature = device.session.sign_auth_challenge(&SERVER_KEY, b"nonce-1").unwrap();

    let key = VerifyingKey::from_bytes(identity.device_signature_key.as_slice().try_into().unwrap()).unwrap();
    let signature = Signature::from_slice(&signature).unwrap();
    let payload = |server: &[u8], nonce: &[u8]| {
        let mut out = b"raindrop/auth/v1\n".to_vec();
        out.extend_from_slice(&(server.len() as u16).to_be_bytes());
        out.extend_from_slice(server);
        out.extend_from_slice(nonce);
        out
    };
    key.verify_strict(&payload(&SERVER_KEY, b"nonce-1"), &signature).unwrap();
    assert!(key.verify_strict(&payload(&SERVER_KEY, b"nonce-2"), &signature).is_err());
    assert!(key.verify_strict(&payload(&[5; 65], b"nonce-1"), &signature).is_err());
}

#[test]
fn pins_from_the_vault_add_trust_but_never_replace_a_key() {
    use raindrop_crypto::backup::BackedUpPin;

    let alice = Device::new("alice", "a1", 34);
    let now = 1_700_000_000;
    alice.session.store().replace_identity("bob", &[1; 32], now).unwrap();

    alice
        .session
        .import_pins(&[
            BackedUpPin {
                user_id: "bob".into(),
                identity_key: vec![2; 32],
                verified: true,
            },
            BackedUpPin {
                user_id: "carol".into(),
                identity_key: vec![3; 32],
                verified: true,
            },
        ])
        .unwrap();

    let bob = alice.session.store().pinned_identity("bob").unwrap().unwrap();
    assert_eq!(bob.identity_key, vec![1; 32]);
    assert!(!bob.verified);
    let carol = alice.session.store().pinned_identity("carol").unwrap().unwrap();
    assert!(carol.verified);
    assert!(alice.session.export_pins().unwrap().iter().any(|p| p.user_id == "carol"));
}

/// Writes the fixture `RaindropServer.Tests/Fixtures/auth_signature.hex` checks the server's sign-in
/// verifier against: `certificate_len: u16 | certificate | nonce: 32 | signature: 64`, for the server
/// key `0x04` followed by 64 bytes of `7`. Run with `cargo test -- --ignored print_auth_fixture --nocapture`.
#[test]
#[ignore]
fn print_auth_fixture() {
    use raindrop_crypto::root::RootSecret;

    let mut server_key = vec![4u8];
    server_key.extend_from_slice(&[7; 64]);
    let nonce = [0x5a; 32];

    let mut device = Device::blank(40);
    let identity = device
        .session
        .create_identity_from_root(
            &RootSecret::from_bytes(&[9; 32]).unwrap(),
            &server_key,
            "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        )
        .unwrap();
    let signature = device.session.sign_auth_challenge(&server_key, &nonce).unwrap();

    let mut out = (identity.certificate.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&identity.certificate);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&signature);
    println!("FIXTURE {}", out.iter().map(|b| format!("{b:02x}")).collect::<String>());
}
