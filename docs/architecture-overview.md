# Architecture overview

RaindropCrypto is a Cargo workspace (`Cargo.toml`, `resolver = "3"`, edition 2024) of two crates. It
sits beside the Flutter client and the .NET server as its own top-level folder, and is not part of
either tree.

```
RaindropCrypto/
  Cargo.toml              workspace; release profile is LTO + one codegen unit
  rustfmt.toml            max_width = 120
  crates/
    raindrop_crypto/      the core (plain Rust, no Flutter)
      src/                session, identity, validation, backup, link, store, provider, error, random
      tests/session.rs    multi-device integration tests
    raindrop_crypto_ffi/  the flutter_rust_bridge layer
      src/api/            hand-written: what Dart can call
      src/frb_generated.rs  generated, never edited
  docs/                   this wiki
```

## What the core does, and does not do

| It does | It does not |
|---|---|
| Make and check identity keys, device certificates and safety numbers | Talk to a server. It never opens a socket |
| Run MLS groups: create, add, remove, rekey, join, merge commits | Decide *when* a commit is accepted. The delivery service orders commits; the caller reports the outcome |
| Encrypt and decrypt group messages, and keep the plaintext | Encode what is inside a message. The payload is opaque bytes; the client owns its format |
| Seal and open the key backup, and the device-link approval | Store the backup or the link. The server holds those as opaque blobs |
| Keep every private key in an encrypted local database | Choose or hold the database key. The client keeps the 32-byte key in the platform keystore |

The client is the only caller of the code. What it needs from the server is described in the server's
[E2EE doc](../../RaindropServer/docs/e2ee.md); the Dart side is in the client's
[crypto doc](../../RaindropClient/docs/crypto.md).

## Modules (`raindrop_crypto/src/`)

| Module | Holds |
|---|---|
| `lib.rs` | Re-exports `Session`, `DeviceIdentity`, `GroupMember`, `Incoming`, `PendingCommit`, `CIPHERSUITE`, `CryptoError`, `Result` |
| `session.rs` | `Session`, the entry point. See [Groups & messages](groups-and-messages.md) and [Identity & trust](identity-and-trust.md) |
| `identity.rs` | `UserIdentity`, `DeviceCertificate`, `safety_number`. See [Identity & trust](identity-and-trust.md) |
| `validation.rs` | `CredentialValidator`, `PinnedIdentityValidator`, `certificate_of` |
| `backup.rs` | `RecoveryKey`, `BackupContents`, `PassphraseCost`, seal/open. See [Key backup](key-backup.md) |
| `link.rs` | `Offer`, `commitment`, sealing and opening the approval. See [Device linking](device-linking.md) |
| `store.rs` | `Store`, `PinnedIdentity`, `CachedMessage`, `open_connection`. See [Local store](local-store.md) |
| `provider.rs` | `RaindropProvider`, the OpenMLS provider, and `JsonCodec` for its stored values |
| `error.rs` | `CryptoError` and the crate's `Result` |
| `random.rs` | `bytes::<N>()`, the one place keys come from (the OS CSPRNG), crate-private |

## How a `Session` is used

A `Session` is one device's state on one server. The client opens one per signed-in server, with the
path of that server's store and its 32-byte key:

```rust
let mut session = Session::open(path, &key)?;      // creates the store on first use
session.create_identity(user_id, device_id)?;      // or restore_identity / complete_device_link
let welcome = ...;                                  // bytes the delivery service handed over
session.join_from_welcome(&welcome)?;
let ciphertext = session.encrypt(&group_id, b"hello")?;
```

`Session` methods fall into the same groups the docs do:

| Group | Methods |
|---|---|
| Identity | `create_identity`, `restore_identity`, `backup_contents`, `device` |
| Session binding | `sign_session_challenge` |
| Message attestations | `sign_message_attestation` (v1), `sign_message_attestation_v2` (a message carrying files) |
| Linking | `begin_device_link`, `approve_device_link`, `complete_device_link` |
| Key packages | `generate_key_packages` |
| Groups | `create_group`, `has_group`, `epoch`, `members`, `group_info`, `add_members`, `remove_members`, `self_update`, `join_by_external_commit`, `join_from_welcome`, `merge_pending_commit`, `discard_pending_commit`, `reset_group`, `delete_group` |
| Messages | `encrypt`, `process`, `receive_message`, `remember_sent`, `export_secret` |
| Trust decisions | `accept_changed_identity`, `pending_identity_changes` |
| Files (module `attachment`, not on `Session`) | `encrypt_file`, `decrypt_file`, `encrypt_bytes`, `decrypt_bytes`, `ciphertext_length` — see [Attachments](attachments.md) |

A few things hold across all of them:

- **Only one identity per store.** `create_identity`, `restore_identity`, `begin_device_link` and
  `complete_device_link` refuse a store that already holds a device identity.
- **Bytes in, bytes out.** Anything that leaves the device (`PendingCommit`, a welcome, a group info, a
  key package, an offer) is `Vec<u8>` for the caller to deliver. Anything that arrives is a slice.
- **Everything that arrives is validated** before it changes state. Certificates are checked for every
  device a call meets; see [Identity & trust](identity-and-trust.md).
- **Secrets are zeroized** (`Zeroizing`, `ZeroizeOnDrop`) wherever they are held in memory.

## Errors

`CryptoError` (`error.rs`) is deliberately coarse; callers branch on the kind, and the detail is for
logs only.

| Variant | Meaning |
|---|---|
| `StoreLocked` | The database could not be opened with that key, or the file is not a Raindrop store |
| `Store(String)` | Any other local database failure |
| `Malformed(String)` | Input from the network or the user was not well formed |
| `Verification(String)` | A signature, certificate or credential did not verify |
| `IdentityChanged { user_id, pinned_key, presented_key }` | A user's identity key differs from the pinned one; both keys are carried. A trust decision for the user; never resolved silently |
| `BackupLocked` | Wrong recovery key or passphrase, or a damaged backup |
| `NotFound(String)` | No group, key or identity with that name exists locally |
| `ResyncRequired` | `process` was given a commit claiming to be this device's own that is not the one it holds as pending (discarded after the server took it, or forged). `reset_group` (keeps the cached messages) and rejoin; see [Groups & messages](groups-and-messages.md#commits-and-epochs) |
| `Mls(String)` | An OpenMLS operation failed (the OpenMLS error type is wrapped as text) |

The bridge maps these onto `CryptoFailureKind`; see [Flutter bridge](flutter-bridge.md#errors).

## Extension points

The core is meant to be opened to third-party plugins along with the rest of Raindrop, so the places
where behaviour may vary are types rather than branches:

- **`CredentialValidator`** (`validation.rs`) is the trait deciding whether a group member is who they
  claim to be. `PinnedIdentityValidator` is the default. It is not yet injectable into a `Session`; see
  [Identity & trust](identity-and-trust.md#the-validator-seam).
- **`RaindropProvider`** is a separate type behind `Session`, so the crypto primitives or MLS storage
  can change without touching the group logic.
- **`CIPHERSUITE`** is a single constant, so a post-quantum suite can be introduced as a new group
  parameter later.
