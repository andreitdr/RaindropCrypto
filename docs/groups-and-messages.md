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

**Raindrop uses one MLS group per channel**, and the group id is the channel's UUID as 16 big-endian
bytes (the same as the server's `Guid.ToByteArray(bigEndian: true)`; the client builds it with
`groupIdForChannel`). `Session` takes group ids as opaque bytes and does not interpret them.

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
   path works.

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
| `join_by_external_commit(group_info)` | A device joining by itself, with nobody online to add it. Returns the group id and a `PendingCommit` to send. The server only accepts this from a device allowed in the channel |
| `group_info(group_id)` | The signed group state an external joiner needs. Upload it after every commit this device merges |

## Sending and receiving

- **`encrypt(group_id, payload)`** encrypts an application payload for everyone in the group. The payload
  is opaque bytes: its encoding is the client's business.
- **`process(message)`** handles one message from the group's delivery stream and returns
  `(group_id, Incoming)`:

  | `Incoming` | Meaning |
  |---|---|
  | `Application { sender, epoch, payload }` | Somebody's message. The sender is identified from the *validated certificate*, not from anything the message claims |
  | `Commit { epoch, added, removed, removed_self }` | A commit moved the group on. It was validated and merged before returning. `removed_self` means this device is no longer in the group |
  | `Proposal` | Stored until somebody commits it |
  | `OwnMessage { epoch }` | This device's own application message echoed back. Its plaintext is already in the cache |

  Note that `process` alone does **not** write to the cache.
- **`receive_message(message_id, sent_at_unix_ms, message)`** is the call for a channel message. It
  decrypts and writes the plaintext to the [message cache](local-store.md#the-message-cache), returning
  the `CachedMessage`. A message already in the cache is returned from there without touching MLS,
  because MLS would refuse to decrypt it a second time. Anything that is not an application message
  (a commit, say) returns `None`.
- **`remember_sent(group_id, message_id, sent_at_unix_ms, payload)`** stores this device's own message,
  which it cannot decrypt from the server's echo.

### Why there is a message cache

MLS deletes each epoch's keys once the group moves on; that is what forward secrecy means. Ciphertext
fetched again from the server later can no longer be decrypted, so **the cache is the only copy of the
plaintext**. History is read from it. Because the plaintext is kept in the same encrypted database as the
device's private keys, losing the store loses the history; a restore from [backup](key-backup.md) brings
back the identity, not old messages ("History is forward-only").

## Exported secrets

`export_secret(group_id, label, context, length)` derives a secret every member of the group can compute
for the *current epoch*, and nobody else can. It is how a voice call gets its media key. `label`
separates uses; `context` binds it further. Because it depends on the epoch, it changes whenever the
group is rekeyed, which is what makes a call's key rotate when somebody leaves.

## Deleting

`delete_group(group_id)` forgets a group entirely (the channel was deleted, or this device left it),
including its cached messages. `Store::delete_message` and `delete_group_messages` remove plaintext
alone; the bridge exposes the first as `forgetMessage`.
