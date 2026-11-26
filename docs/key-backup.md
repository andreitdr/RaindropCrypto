# Key backup

The backup is what a user restores onto a new device when every old one is gone. Code: `backup.rs`, and
`Session::backup_contents` / `restore_identity`.

It is sealed on the device and stored on the server as an **opaque blob** (the server keeps up to 64 KiB
per user and cannot read it). What unlocks it is either a recovery key or a passphrase. The server
side is in the server's [E2EE doc](../../RaindropServer/docs/e2ee.md#key-backup).

## What is in it

`BackupContents`:

| Field | Why |
|---|---|
| `user_id` | Whose identity this is |
| `user_identity_secret` | The 32-byte identity secret, so a restored device can certify itself and keep the same safety numbers |
| `pinned_identities` (`BackedUpPin`: user id, identity key, `verified`) | So the user's trust decisions survive the move |

**There are no message keys in a backup.** History is forward-only: MLS deletes old epoch keys, so there
is nothing to back up, and a restored device starts with an empty [message cache](local-store.md#the-message-cache).

## Two ways to unlock it

| | Recovery key | Passphrase |
|---|---|---|
| Secret | 256 random bits, shown **once** as 24 BIP-39 words | Whatever the user chooses |
| Key derivation | None: the 256 bits are the key | Argon2id (v0x13) |
| Seal | `seal_with_recovery_key` | `seal_with_passphrase` |
| Open | `open_with_recovery_key` | `open_with_passphrase` |

`RecoveryKey::from_words` forgives case and extra whitespace, and a typo is caught by the BIP-39 checksum
rather than producing a wrong key. `needs_passphrase(blob)` says which kind a blob is, so the client
knows what to ask for.

The bridge's `seal_backup_with_recovery_key` generates a fresh key and returns the blob together with the
words to show the user once. The words must then be dropped.

### Passphrase cost

`PassphraseCost` defaults to **256 MiB, 3 passes, parallelism 1**: each guess is expensive for anybody
holding a copy of the blob, which includes the server. The cost is stored in the blob, so it can be
raised later without invalidating old backups.

A blob is attacker-controlled input, so `open_with_passphrase` refuses costs outside the range this code
would produce, before running the KDF: memory below 19 MiB or above 512 MiB, iterations of 0 or more than
10, or parallelism of 0 or more than 8, fails with `Malformed`. The limits sit above the default and the
test cost, and low enough that a phone is not killed by a blob the server edited.

## Blob layout

All fields big-endian:

```text
"RDBK" | version: u8 = 1 | kdf: u8 (0 = recovery key, 1 = Argon2id)
       | [kdf = 1: memory_kib: u32 | iterations: u32 | parallelism: u32 | salt: 16 bytes]
       | nonce: 24 bytes | XChaCha20-Poly1305 ciphertext of the JSON contents
```

| Part | Length |
|---|---|
| Header, recovery key | 6 bytes |
| Header, Argon2id | 34 bytes (6 + 12 + 16) |
| Nonce | 24 bytes |
| Minimum ciphertext | 16 bytes (the tag) |

**Everything before the nonce is the AEAD's associated data**, so the KDF parameters cannot be weakened in
storage without the blob failing to open. A wrong key, a wrong passphrase and a tampered blob all come
back as `CryptoError::BackupLocked`; a blob that is not a Raindrop backup at all is `Malformed`.

The layout is listed with the other shared formats in [Wire contracts](wire-contracts.md#key-backup-blob).

## Restoring

`restore_identity_with_recovery_key` and `restore_identity_with_passphrase` (bridge) open the blob and
call `Session::restore_identity`, which installs the identity with a **new device key**, and replaces
the pins with the backed-up ones (marking verified those that were). The new device is then registered
with the server like any other.
