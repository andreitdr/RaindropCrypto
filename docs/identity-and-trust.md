# Identity & trust

MLS authenticates *signature keys*; it says nothing about which person a key belongs to. Raindrop
answers that with a **device certificate** carried in every MLS credential, and a **validator** that
checks it. Code: `identity.rs`, `validation.rs`, `store.rs` (the pins), and the identity half of
`session.rs`.

## The model

- **One identity key per user** (`UserIdentity`, Ed25519). The private half exists only on the user's
  own devices and inside their [sealed backup](key-backup.md). The server stores the public half so other
  users can fetch it, but can never sign with it.
- **One signature key per device**, made when the device is set up and held in MLS storage. It is the
  key the device signs its MLS messages with.
- **A certificate binds the two.** The identity key signs a `DeviceCertificate` saying "this device
  signature key belongs to `(user id, device id)`". The certificate's bytes are the *identity* of the
  device's `BasicCredential`, so every group member can check every leaf.

A server that invents a device for somebody cannot produce the certificate. A server that swaps a
user's identity key trips the pin.

## `DeviceCertificate`

| Field | Meaning |
|---|---|
| `user_id`, `device_id` | Text (UUIDs in practice; the server refuses anything else) |
| `device_signature_key` | The device's Ed25519 MLS signature public key |
| `user_identity_key` | The identity key that signed this. Carried so a verifier can pin it on first sight; it is only trusted after being compared with the pin |
| `created_at_unix` | Seconds |
| `signature` | Ed25519 over `context ‖ version ‖ every field above`, each field length-prefixed |

`verify()` checks the signature against the identity key the certificate carries (`verify_strict`). It
answers "is this certificate internally consistent", not "is this the right person". That second
question is the validator's. The byte layout is in [Wire contracts](wire-contracts.md#device-certificate).

## Credential validation

`validation.rs` is the one place a member's credential is judged.

- **`certificate_of(credential, signature_key)`** reads the certificate out of a credential and checks
  that it is well formed, is about *this leaf's* signature key, and verifies. Only `BasicCredential`s
  are accepted.
- **`CredentialValidator`** is the trait: `validate(&self, credential, signature_key) ->
  Result<DeviceCertificate>`.
- **`PinnedIdentityValidator`** is the default rule. It runs `certificate_of`, then pins the
  certificate's identity key for that user: a user seen for the first time is pinned there and then
  (**trust on first use**); a user whose key differs from the pin is refused with
  `CryptoError::IdentityChanged`.

`Session` validates **every** device it meets, not just the ones it adds:

| Where | What is checked |
|---|---|
| `add_members` | Each key package's leaf, before anything is committed |
| `join_from_welcome` | Every member of the staged group, before it is joined |
| `join_by_external_commit` | Every existing member (other than itself) of the group joined; on a refusal the group is deleted again, since OpenMLS has already stored it |
| `process` | The sender of an application message; every added device, updated leaf and the committer's new leaf in an incoming commit. See [Refused after decryption](#refused-after-decryption) for what a refusal here costs |

### Pins

Pins live in the encrypted [local store](local-store.md) (`rd_peer_identities`).

- `pin_identity` pins on first sight and returns the pin in force. A different key for a pinned user is
  refused and **changes nothing**.
- `replace_identity` accepts a changed key. It is the only way to move a pin, it resets `verified`, and
  the client calls it (through `Session::accept_changed_identity`) only after the user has looked at the
  new safety number.
- `mark_verified` records that the user compared safety numbers and they matched. It needs the exact key,
  so it cannot confirm a key that has since changed.
- A user's **own** identity key is pinned and marked verified when the identity is installed.

`IdentityChanged` is never resolved silently. It carries everything the client needs to put the change in
front of the user and to accept it: `IdentityChanged { user_id, pinned_key, presented_key }`, where
`pinned_key` is the key this device trusted until now (empty if it has no pin, which the bridge reports
as none) and `presented_key` is the key the certificate in front of it carried. The client shows the
safety number for each and, on acceptance, passes `presented_key` — exactly that key — to
`accept_changed_identity`; a different key releases and clears nothing.

### Refused after decryption

OpenMLS decrypts a message, and **spends its key**, before `process` gets to check who sent it: the
ratchet update is stored as `process_message` returns. A refusal at that point cannot be retried, so
`process` does not simply drop what it refused:

- **An application message from a changed identity is held.** `receive_message` writes its plaintext
  and metadata, with the identity key the sender's certificate carried, to `rd_held_messages` (the same
  SQLCipher store as the message cache; see [Local store](local-store.md#held-messages)) and returns
  `IdentityChanged`, as it does every time that message is asked for again.
  **`Session::accept_changed_identity(user_id, identity_key)`** replaces the pin and moves every message
  held for that user *under that key* into the message cache, so `cached_messages` and `receive_message`
  return it from then on; it returns how many it released (the bridge drops the count). Messages held
  under any other key stay held. A change the user never accepts leaves its messages held — nothing
  deletes them on a timer — until the group is deleted (`delete_group`) or the store is.
- **Any other refusal of an application message** (`Verification`: a certificate that does not verify, a
  sender not in the group) is returned as before, holding nothing. It is not a decision the user could
  reverse.
- **A commit that fails any check** (`IdentityChanged` or `Verification`) **takes the device out of the
  group.** The commit cannot be processed again and every later commit builds on it, so the group would
  be stuck at that epoch for good. `process` deletes the group (and the `pending_commit.<hex>` record)
  before returning the error, keeping its cached and held messages. The caller rejoins by external
  commit after the user decides; the join validates every member again, so it is refused with the same
  error until the change is accepted. `Session::process` alone, which has no message id, cannot hold an
  application message: it returns the error and the plaintext is lost, which is why channel messages go
  through `receive_message`.

### Pending changes survive a restart

A held message or a group left because of a changed key is a decision the user has not made yet, and the
app can be closed before they make it. So the core writes both down, in the same SQLCipher store, and
`Session::pending_identity_changes()` lists them (bridged as `CryptoSession.pending_identity_changes`):

| Field | Meaning |
|---|---|
| `user_id`, `presented_key` | One entry per user and key they presented |
| `pinned_key` | The key pinned for them now, if any |
| `held_messages`, `held_group_ids` | How many of their messages are held under that key, and in which groups |
| `left_group_ids` | The groups this device left (or was refused joining) because of that key |

The held part is read from `rd_held_messages`. The left part comes from `rd_identity_left_groups`
([Local store](local-store.md#groups-left-for-a-changed-identity)), which `process` writes when it takes
the device out of a group for a refused commit, and `join_by_external_commit` / `join_from_welcome` write
when a join is refused for `IdentityChanged`. Only that refusal is recorded; a `Verification` failure is
not something the user could reverse.

An entry ends when:

- **the key is accepted**: `accept_changed_identity(user_id, presented_key)` replaces the pin, releases
  the held messages, and clears the left-group records for that user and key, in that order, so a failure
  part way leaves something still pending and accepting again finishes the job. Because accepting clears
  the record, **read `left_group_ids` first** to know which groups to join again (the client does, inside
  its serial group queue). A rejoin that never happens is only postponed: the next use of the channel
  joins it, as for any channel the device is not in;
- **the group is joined again** (`join_by_external_commit`, `join_from_welcome`) or **created**
  (`create_group`): the device is in it, so the record is stale;
- **the group is deleted** (`delete_group`, through `delete_group_messages`). `reset_group` keeps it: the
  device is about to rejoin, and the join will refuse again until the key is accepted.

Nothing here accepts a key. Listing, announcing and recording only report the decision that is waiting.

### The validator seam

`CredentialValidator` is a trait so a plugin, or a stricter deployment, can add rules of its own, such as
requiring every identity to be verified before a member may be added.

**Today the default is fixed.** `Session::validator()` builds a `PinnedIdentityValidator` directly, and
the bridge exposes no way to supply another. Making the validator injectable (a `Session` constructor or
setter taking a `Box<dyn CredentialValidator>`, then a bridge hook) is the work that turns this trait
into a real plugin seam. Until then, a custom rule means changing `session.rs`.

## Safety numbers

`safety_number(user_a, key_a, user_b, key_b)` returns the **60 digits** two users read to each other (or
scan as a QR code) to confirm neither identity key was swapped in transit. It is symmetric: both sides
compute the same digits regardless of argument order (the two halves are ordered by user id).

Each half is Signal's construction: SHA-512 over `0x0000 ‖ identity key ‖ user id`, then iterated **5200**
times (each round hashing the previous digest with the identity key), and the first 30 bytes read as six
5-byte groups, each reduced modulo 100,000 to five digits.

## Session binding

A password opens a *session* on the server; a device key **binds** it, proving the session runs on a
device that holds the key. `Session::sign_session_challenge(nonce)` signs
`"raindrop/session-binding/v1\n" ‖ nonce` with the device's signature key (plain Ed25519; a test pins
this). The server checks it against the device key in the certificate it stored. The prefix means the
signature is good for nothing else. The server side, including which actions need a bound session, is
in the server's [E2EE doc](../../RaindropServer/docs/e2ee.md).

## Creating and restoring an identity

| Call | When | Identity key | Device key |
|---|---|---|---|
| `create_identity(user_id, device_id)` | The user's first device | New | New |
| `restore_identity(backup, device_id)` | Every old device is gone; the [backup](key-backup.md) is opened | From the backup (so peers' safety numbers do not change) | New |
| `complete_device_link(approval)` | An existing device approved this one; see [Device linking](device-linking.md) | From the approval | Made at `begin_device_link` |

Restoring also brings back the identity pins the user had made, verified flags included, so trust
decisions survive the move.
