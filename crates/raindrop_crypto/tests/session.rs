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
    let (group_id, pending) = carol.session.join_by_external_commit(&group_info).unwrap();
    assert_eq!(group_id, CHANNEL);
    carol.session.merge_pending_commit(CHANNEL).unwrap();

    for existing in [&alice, &bob] {
        let (_, incoming) = existing.session.process(&pending.commit).unwrap();
        assert!(matches!(incoming, Incoming::Commit { .. }));
    }

    let hello = send(&carol, "m1", "hi all");
    assert_eq!(receive(&alice, "m1", &hello), "hi all");
    assert_eq!(receive(&bob, "m1", &hello), "hi all");
    assert_eq!(alice.session.members(CHANNEL).unwrap().len(), 3);
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
    assert!(matches!(result, Err(CryptoError::IdentityChanged { ref user_id }) if user_id == "bob"));
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
    let (_, pending) = replacement.session.join_by_external_commit(&group_info).unwrap();
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

    let (offer, commitment) = phone.session.begin_device_link("alice", "alice-phone").unwrap();
    let approval = alice.session.approve_device_link(&offer, &commitment).unwrap();
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

    let (_, commitment) = phone.session.begin_device_link("alice", "alice-phone").unwrap();
    // The server swaps in an offer of its own; the code the user carried does not match it.
    let (substituted, _) = attacker.session.begin_device_link("alice", "alice-phone").unwrap();
    assert!(matches!(
        alice.session.approve_device_link(&substituted, &commitment),
        Err(CryptoError::Verification(_))
    ));

    // An offer for a different user is refused even with a matching code.
    let (for_bob, bob_code) = attacker.session.begin_device_link("bob", "x").unwrap();
    assert!(alice.session.approve_device_link(&for_bob, &bob_code).is_err());

    let _ = (&mut phone, &mut attacker);
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
