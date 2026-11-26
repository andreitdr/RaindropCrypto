# Local store

Each device keeps one encrypted database per server profile. Code: `store.rs` (Raindrop's own tables),
`provider.rs` (the OpenMLS storage in the same file), and the client's `CryptoStores` for where the file
and key live.

It holds everything a device must never lose to a stolen disk or a backup of the app's data folder: its
private keys, the MLS group state, the identity keys it has pinned for other users, the
**decrypted message cache**, and the **held messages** waiting on a trust decision.

## Opening it

`Store::open(path, key)` (and `Session::open`, which opens the store and the MLS provider):

- **SQLCipher**, keyed with a **raw 32-byte key** (`PRAGMA key = "x'<hex>'"`), not a passphrase. SQLCipher
  then skips its own PBKDF2, which would only slow every open for a key that is already random.
- The key is only checked when a page is first read, so `open_connection` reads `sqlite_master` right away
  and a wrong key comes back as **`CryptoError::StoreLocked`** rather than a failure somewhere later.
- The 5-second busy timeout is set **before** that first read, so a brief lock from another connection
  waits instead of failing. Only SQLite's "file is not a database" (a wrong key) becomes `StoreLocked`;
  any other failure (busy, I/O) is `CryptoError::Store` with the detail.
- Then `journal_mode = WAL`, `foreign_keys = ON`, `secure_delete = ON`.
- The key type is `StoreKey = Zeroizing<[u8; 32]>`. The **client** keeps the key in the platform
  keystore (`flutter_secure_storage`), never beside the file. This crate never chooses or stores it.

**Two connections, one file.** OpenMLS's storage provider owns one connection and `Store` another; WAL
mode lets them coexist. `RaindropProvider` serialises OpenMLS's stored values as JSON (`JsonCodec`) and
runs the storage crate's own migrations on open.

SQLCipher's crypto library is chosen per target in `crates/raindrop_crypto/Cargo.toml`: CommonCrypto
on Apple platforms, and a vendored OpenSSL elsewhere so Android, Linux and Windows builds need nothing
installed. `rusqlite` stays on the same major version as `openmls_sqlite_storage`, so both use the one
SQLCipher build.

## Tables

`Store::open` creates what is missing (`CREATE TABLE IF NOT EXISTS`); there is no migration mechanism for
Raindrop's own tables, so a column added to an existing table would need a guarded `ALTER`. A new table
(like `rd_held_messages` and `rd_identity_left_groups`) is simply created the next time an older store is opened.

### The meta table

`rd_meta(key TEXT PRIMARY KEY, value BLOB)` holds this device's own secrets and settings
(`get_meta` / `put_meta` / `delete_meta`; reads come back `Zeroizing`).

| Key | Value |
|---|---|
| `identity.user_id` | The user's id |
| `identity.device_id` | This device's id |
| `identity.uik_secret` | The user identity secret (32 bytes) |
| `identity.device_signature_public` | The device signature public key (its private half is in the MLS storage) |
| `identity.device_certificate` | The certificate bytes |
| `link.offer` | An unfinished [device link](device-linking.md)'s offer |
| `link.exchange_secret` | Its X25519 secret |
| `link.code_secret` | Its link code's 16-byte code secret |
| `pending_commit.<group id in hex>` | SHA-256 of the exact bytes of this device's pending commit for that group, while it is pending. Written by `add_members`, `remove_members` and `self_update`; deleted on merge, discard, `reset_group`, `delete_group`, and when another member's commit takes the epoch. See [Groups & messages](groups-and-messages.md#commits-and-epochs) |

### Identity pins

`rd_peer_identities(user_id PK, identity_key, verified, first_seen)`: other users' identity keys as this
device pinned them. See [Identity & trust](identity-and-trust.md#pins).

### The message cache

`rd_messages(group_id, message_id, sender_user_id, sender_device_id, epoch, sent_at, payload,
PK(group_id, message_id))`, indexed on `(group_id, sent_at)`.

**This is the only copy of the plaintext.** MLS deletes each epoch's keys once it moves on, so the
ciphertext cannot be decrypted a second time.

- `put_message` is `INSERT OR IGNORE`: a message can only be decrypted once, so a second arrival is an
  echo and the first copy is kept.
- `messages(group_id, before_unix_ms, limit)` returns the newest `limit` messages sent before a time (or
  the newest overall), **newest first**, ordered by `(sent_at, message_id)` descending. It is what the
  client's `cachedMessages` reads.
- `payload` is the inner message in its wire encoding. The client decodes it; the core never does.
- `delete_message` and `delete_group_messages` remove plaintext when a message or its channel is deleted,
  from this table and from the held messages alike. `Session::reset_group` deliberately does **not** call
  them: a device that drops its MLS state to rejoin keeps the cache, which is the only copy of its history. With `secure_delete` on, the freed pages are
  overwritten.

### Held messages

`rd_held_messages(group_id, message_id, sender_user_id, sender_device_id, sender_identity_key, epoch,
sent_at, payload, PK(group_id, message_id))`, indexed on `(sender_user_id, sender_identity_key)`.

Messages MLS decrypted (spending their key) whose sender's identity key no longer matched the pin, kept
for the user's decision instead of lost; see [Identity & trust](identity-and-trust.md#refused-after-decryption).
The same columns as the message cache plus the identity key the sender's certificate carried. It is in
the same SQLCipher file, so held plaintext is exactly as protected as cached plaintext.

- `hold_message` is `INSERT OR IGNORE`, like `put_message`.
- `held_message_origin(group_id, message_id)` says whether a message is held, from whom and under which
  identity key, so `receive_message` answers `IdentityChanged` (with both keys) again rather than trying
  MLS a second time.
- `held_messages(group_id)` lists a group's held messages, oldest first.
- `release_held_messages(user_id, identity_key)` moves every message held for that user under that key
  into `rd_messages`, in one transaction, and returns how many; `Session::accept_changed_identity` calls
  it. Rows under any other key stay.
- Nothing expires a held message. `delete_message`, `delete_group_messages` (and so `delete_group`) and
  deleting the store remove them; `reset_group` leaves them.

### Groups left for a changed identity

`rd_identity_left_groups(group_id, user_id, presented_key, recorded_at, PK(group_id, user_id))`: the groups
this device is out of **because** a member's commit was refused (or a join was refused) for
`IdentityChanged`, with the key the member presented. One row per group and user; a second refusal for the
same pair replaces the key, since the user may have changed it again. It is how the list of groups to join
again after the user accepts a key survives a restart, and it is in the same SQLCipher file.

- `record_left_group(group_id, user_id, presented_key, now)` upserts. `Session` calls it when it refuses
  a commit (after `reset_group`) and when a join is refused; nothing else writes it.
- `clear_left_groups(user_id, presented_key)` removes the rows for that user under that key, called by
  `Session::accept_changed_identity`. Rows under another key stay.
- `forget_left_group(group_id)` removes a group's rows: a successful join, `create_group`, and
  `delete_group_messages` (so `delete_group`). `reset_group` leaves them.
- `pending_identity_changes()` joins them with `rd_held_messages` (grouped by sender, key and group) and
  the pin from `rd_peer_identities`, into one `PendingIdentityChange` per user and key. All queries are
  parameterised.

## What the file looks like on disk

Nothing readable: a test checks that the SQLite header and a marker value are absent from both the
database file and its WAL. A wrong key is refused, and the right key still opens it.

## Where the file and key live

Not this crate's concern, but for orientation: the client keeps the store at
`<app support>/crypto/raindrop-<serverId>.db`, with its key as `server.<id>.dbkey` in `SecureStore`, and
deletes both when a server is forgotten. See the client's [crypto doc](../../RaindropClient/docs/crypto.md).
