# Groups & messages

Everything a device does with MLS goes through [`Session`](architecture-overview.md#how-a-session-is-used)
(`session.rs`). This page covers groups, commits, joining, and encrypting and receiving messages.

Status: the Rust side is complete and covered by tests, and the server's
[MLS delivery service](../../RaindropServer/docs/e2ee.md#the-delivery-service) — where a commit,
Welcome, key package or group info actually goes — is implemented and exercised by the client's
`E2eeApi` wrapper against a live server. What is not there yet is the app *driving* a channel's group
through it: nothing in the app calls `create_group`, `add_members` or `encrypt` for a real channel, so
no encrypted text message has shipped yet. See [Roadmap](README.md#quick-facts).

## Groups

**Raindrop uses one MLS group per channel** at a time, and the group id is the channel's UUID as 16
big-endian bytes (the same as the server's `Guid.ToByteArray(bigEndian: true)`; the client builds it with
`groupIdForChannel`). A channel whose group could no longer be followed is given a new one — a new
**generation** ([Replacing a broken group](#replacing-a-broken-group)) — whose id is those 16 bytes followed
by the generation as 8 big-endian bytes; generation 0 keeps the plain 16. `Session` takes group ids as
opaque bytes and does not interpret them, so generations needed no change here: a new generation is just
another group, and the [message cache](local-store.md#the-message-cache) is keyed by group id, so each
generation's history stays under its own.

Groups are built with:

| Setting | Value | Why |
|---|---|---|
| Ciphersuite | `CIPHERSUITE` = `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | MLS's mandatory-to-implement suite, in one constant so a post-quantum suite can arrive as a new group parameter |
| Padding | 256 bytes | Messages are padded to a multiple of this, so their size says less about what they contain |
| Max past epochs | 2 | A message sent just before a commit still decrypts when it arrives just after. Small on purpose: every kept epoch is forward secrecy postponed |
| Ratchet tree extension | on | Welcomes and group infos carry the tree, so a joiner needs nothing else |
| Wire format policy | Mixed in, ciphertext out | Outgoing messages are always encrypted; incoming may be either |

## Key packages

`generate_key_packages(count, last_resort)` makes `count` one-time key packages, for the server to hand
out so others can add this device while it is offline. Pass `last_resort` for the single reusable one
the server falls back to when the one-time ones run out. Each embeds this device's credential (and
so its certificate).

## Commits and epochs

Any change to a group (adding or removing devices, rotating keys) produces a **pending commit**:

```rust
pub struct PendingCommit {
    pub commit: Vec<u8>,          // for everyone already in the group
    pub welcome: Option<Vec<u8>>, // for the devices the commit adds, if any
    pub epoch_after: u64,         // the epoch once merged
}
```

The caller sends it to the server, which accepts **exactly one commit per epoch**:

1. The server accepts: call `merge_pending_commit` (returns the new epoch).
2. Another commit won: call `discard_pending_commit`, `process` the winning commit, and retry if the
   change is still needed.
3. The server fans the device's own commit back out: `process` recognises it and merges it, so either
   path works — **but only if it is the commit this device still holds as pending.**

OpenMLS reports a commit as this device's own (`OwnPrivateMessage`) from the encrypted sender data
alone, which is not authenticated — any member can derive those keys and forge it — and the author
cannot decrypt its own commit to check. So `add_members`, `remove_members` and `self_update` record
SHA-256 of the exact commit bytes they return (the `pending_commit.<group id>` meta key, see
[Local store](local-store.md#the-meta-table)), and `process` merges an "own" commit only when a commit is
pending **and** SHA-256 of the message as received matches, compared in constant time. The record goes
with the pending commit: `merge_pending_commit`, `discard_pending_commit`, `reset_group`, `delete_group`, an echoed
own commit merging, and another member's commit taking the epoch all delete it.

Any other "own" commit is **`CryptoError::ResyncRequired`**, with nothing merged and the epoch
unchanged (a different commit that is pending stays pending). Two cases reach it: the server stored the
commit but answered with an error, so the device discarded it and the group moved on without it; or a
member forged it. Either way the local group can no longer follow the server's, and the caller
`reset_group`s it (keeping the cached messages, see [Resetting and deleting](#resetting-and-deleting)) and
rejoins (the client by external commit). Own application messages are unaffected and still
return `OwnMessage`.

| Call | Produces |
|---|---|
| `add_members(group_id, key_packages)` | A commit and a welcome. Every key package's certificate is checked (and its user pinned) before anything is committed |
| `remove_members(group_id, leaf_indices)` | A commit removing devices by leaf index; their keys stop working at the next epoch |
| `self_update(group_id)` | A commit rotating this device's keys, moving everyone to a new epoch. Used to rekey calls when somebody leaves, and periodically |

`members(group_id)` lists every device in the group as a `GroupMember { leaf_index, user_id,
device_id }`, with the user and device read from the certificate.

## Joining

| Call | For |
|---|---|
| `join_from_welcome(welcome)` | A device that was added. Every member of the staged group is validated first. Returns the group id |
| `join_by_external_commit(expected_group_id, group_info)` | A device joining by itself, with nobody online to add it. Returns the group id and a `PendingCommit` to send. The server only accepts this from a device allowed in the channel. See [External joins](#external-joins) |
| `group_info(group_id)` | The signed group state an external joiner needs. Upload it after every commit this device merges |

### External joins

`join_by_external_commit(expected_group_id, group_info)` takes the group id the caller means to join (the
channel's id) because the group info comes from the server, which must not choose the group:

- A group info for a different group is refused with `Verification` before anything is built.
- A group this device already holds is refused with `Store`, so a join can never overwrite it.
- OpenMLS stores **and merges** the group as it builds the commit, so the group is at its new epoch
  before the server has seen the commit. Every existing member is validated after that; if any fails
  (`IdentityChanged`, `Verification`) the group is deleted again before the error returns, so a group
  built on a server-supplied ratchet tree is never left in storage.
- `epoch_after` is the epoch the device is already at (`epoch(group_id)` returns the same number). The
  caller's `merge_pending_commit` once the server accepts the commit is a no-op that returns it again;
  if the server refuses the commit (another one won the epoch), call `reset_group` (not `delete_group`:
  the device may hold history from an earlier membership) and join again from the newer group info.

## Sending and receiving

- **`encrypt(group_id, payload)`** encrypts an application payload for everyone in the group. The payload
  is opaque bytes: its encoding is the client's business.
- **`process(message)`** handles one message from the group's delivery stream and returns
  `(group_id, Incoming)`:

  | `Incoming` | Meaning |
  |---|---|
  | `Application { sender, epoch, payload }` | Somebody's message. The sender is identified from the *validated certificate*, not from anything the message claims |
  | `Commit { epoch, added, removed, removed_self }` | A commit moved the group on. It was validated and merged before returning. `removed_self` means this device is no longer in the group |
  | `Proposal` | Never returned. Raindrop changes a group only by commit, so a standalone proposal (including an external join proposal from a non-member) is refused with `Verification` and never stored; it is kept only so the bridge's `ProcessedKind` does not change |
  | `OwnMessage { epoch }` | This device's own application message echoed back. Its plaintext is already in the cache |

  An own commit this device does not hold as pending is not returned at all but refused with
  `ResyncRequired`; see [Commits and epochs](#commits-and-epochs).

  **A commit that fails validation (`IdentityChanged`, `Verification`) deletes the group** before the
  error returns, with its `pending_commit.<hex>` record but not its cached messages: MLS spent the key
  that decrypted it, so the group could never move past it. Refusing a commit is leaving the group;
  rejoin by external commit once the cause is dealt with (for a changed identity, once the user has
  accepted it — the join validates every member again). An application message refused for its
  sender's changed identity is `IdentityChanged`, and from `process` its plaintext is lost; see
  `receive_message` below and [Identity & trust](identity-and-trust.md#refused-after-decryption).

  Note that `process` alone does **not** write to the cache.
  `add_members`, `remove_members` and `self_update` also clear the group's proposal store before
  committing, so a commit only ever carries the proposals this device made for it.
- **`receive_message(message_id, sent_at_unix_ms, message)`** is the call for a channel message. It
  decrypts and writes the plaintext to the [message cache](local-store.md#the-message-cache), returning
  the `CachedMessage`. A message already in the cache is returned from there without touching MLS,
  because MLS would refuse to decrypt it a second time. Anything that is not an application message
  (a commit, say) returns `None`. A message from a sender whose identity key changed is **held**
  (`rd_held_messages`, see [Local store](local-store.md#held-messages)) and returns `IdentityChanged`,
  now and every time it is asked for again, until `accept_changed_identity` moves it into the cache.
- **`remember_sent(group_id, message_id, sent_at_unix_ms, payload)`** stores this device's own message,
  which it cannot decrypt from the server's echo.

### Why there is a message cache

MLS deletes each epoch's keys once the group moves on; that is what forward secrecy means. Ciphertext
fetched again from the server later can no longer be decrypted, so **the cache is the only copy of the
plaintext**. History is read from it. Because the plaintext is kept in the same encrypted database as the
device's private keys, losing the store loses the history; a restore from [backup](key-backup.md) brings
back the identity, not old messages ("History is forward-only").

## Replacing a broken group

The delivery service cannot read a commit, so it accepts one that no member can process: garbage that does
not decrypt, or a commit adding a device whose certificate does not verify. What the core does with it:

- A commit that does not decrypt or parse is refused (`Mls`/`Malformed`, reaching the client as
  `CryptoFailureKind::Other`/`Malformed`) and **changes nothing**: the group stays at its epoch, so every
  later `process` of the log stops at the same commit.
- A commit that fails validation (`Verification`) resets the group, as above.

Neither is recoverable inside the group: every later commit builds on the broken one. The client
(`ChannelGroups`, see [its doc](../../RaindropClient/docs/crypto.md)) resets its copy, tries once to rejoin
from the published group info, and otherwise reports the commit to the server, which starts a new generation
of the channel's group (see the server's
[Recovering a broken group](../../RaindropServer/docs/e2ee.md#recovering-a-broken-group)). The core's part
is unchanged: `create_group` for the new id, `join_by_external_commit` / `join_from_welcome` into it with
every member validated, and `reset_group` on the old one, which keeps its cached messages. Nothing about a
new generation is trusted that a new group would not be.

A `ResyncRequired` or `IdentityChanged` is not a broken group: the first is this device's own copy falling
behind (reset and rejoin), the second is the user's decision.

## Exported secrets

`export_secret(group_id, label, context, length)` derives a secret every member of the group can compute
for the *current epoch*, and nobody else can. It is how a voice call gets its media key. `label`
separates uses; `context` binds it further. Because it depends on the epoch, it changes whenever the
group is rekeyed, which is what makes a call's key rotate when somebody leaves.

## Resetting and deleting

The message cache is the only copy of plaintext: MLS deletes an epoch's keys once the group moves on, so
ciphertext fetched again later cannot be decrypted. Two calls drop a group, and the difference is whether
that copy goes with it.

- `reset_group(group_id)` drops the MLS group state and forgets the pending-commit record, and **keeps the
  cached and held messages**. It is for every case where the device is going to rejoin: a
  `ResyncRequired`, a server that says the device is too far behind, a refused or failed external join
  (including `epoch_conflict`), a lost group-creation race. It does nothing if the group is not held.
  Rejoining afterwards (`join_by_external_commit`, `join_from_welcome`) works over the surviving cache:
  `receive_message` answers a message id that is cached from the cache without asking MLS, and
  `put_message` is `INSERT OR IGNORE`, so a message that reappears collides with nothing. The group
  deletion `process` does on refusing a commit is a `reset_group`.
- `delete_group(group_id)` is `reset_group` plus `delete_group_messages`: the group is gone for this
  device for good (the channel was deleted, or this device was removed from it), so its cached and held
  messages go too.

`Store::delete_message` and `delete_group_messages` remove plaintext alone; the bridge exposes the first
as `forgetMessage`.
