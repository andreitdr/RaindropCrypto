# Local store

Each device keeps one encrypted database per server profile. Code: `store.rs` (Raindrop's own tables),
`provider.rs` (the OpenMLS storage in the same file), and the client's `CryptoStores` for where the file
and key live.

It holds everything a device must never lose to a stolen disk or a backup of the app's data folder: its
private keys, the MLS group state, the identity keys it has pinned for other users, and the
**decrypted message cache**.

## Opening it

`Store::open(path, key)` (and `Session::open`, which opens the store and the MLS provider):

- **SQLCipher**, keyed with a **raw 32-byte key** (`PRAGMA key = "x'<hex>'"`), not a passphrase. SQLCipher
  then skips its own PBKDF2, which would only slow every open for a key that is already random.
- The key is only checked when a page is first read, so `open_connection` reads `sqlite_master` right away
  and a wrong key comes back as **`CryptoError::StoreLocked`** rather than a failure somewhere later.
- Then `journal_mode = WAL`, `foreign_keys = ON`, `secure_delete = ON`, and a 5-second busy timeout.
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
Raindrop's own tables, so a column added to an existing table would need a guarded `ALTER`.

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
- `delete_message` and `delete_group_messages` remove plaintext when a message or its channel is deleted.
  With `secure_delete` on, the freed pages are overwritten.

## What the file looks like on disk

Nothing readable: a test checks that the SQLite header and a marker value are absent from both the
database file and its WAL. A wrong key is refused, and the right key still opens it.

## Where the file and key live

Not this crate's concern, but for orientation: the client keeps the store at
`<app support>/crypto/raindrop-<serverId>.db`, with its key as `server.<id>.dbkey` in `SecureStore`, and
deletes both when a server is forgotten. See the client's [crypto doc](../../RaindropClient/docs/crypto.md).
