# Root identity, vault and pairing

One person, one identity, on every device they pair and every server they join — with no central
service and without any two servers being able to tell their accounts belong to the same person.

Code: `root.rs`, `pairing.rs`, and four `Session` methods (`create_identity_from_root` and
`create_identity_from_root_for`, `sign_auth_challenge`, `export_pins` / `import_pins`). Bridge: `api/identity.rs`.

> **Status.** The core, its bridge functions and its tests are in place, and the server accepts the
> sign-in signature and stores and relays the blobs (`RaindropServer/docs/e2ee.md`). The client is built on it
> ([its identity doc](../../RaindropClient/docs/identity.md)). No longer called by the client, and due to be removed:
> the randomly generated per-server identity ([Identity & trust](identity-and-trust.md)),
> [Device linking](device-linking.md) and the per-server [Key backup](key-backup.md).

## The root secret

`RootSecret` is 32 random bytes, made once (`RootSecret::generate`) on a person's first device. It lives
only on their paired devices; the client keeps it in the platform's secure storage, behind a biometric
or system unlock, or behind an app PIN where the device has neither.

For a server whose long-lived identity key is `server_key`, `RootSecret::account(server_key)` derives,
with HKDF-SHA256 (no salt; `info` is a context string followed by the server key):

| Derived | Context | Use |
|---|---|---|
| User id (16 bytes, shaped as a version-4 UUID) | `raindrop/root/user-id/v1\n` | The account's id on that server |
| User identity key seed (32 bytes) | `raindrop/root/identity-key/v1\n` | The Ed25519 `UserIdentity` that certifies the person's devices there |
| Vault key (32 bytes) | `raindrop/root/vault-key/v1\n` | Seals the vault stored on that server |

What follows from that:

- **Any paired device can join or re-join any server by itself.** It derives the account, makes its own
  random device key as before, and certifies it with the derived identity key
  (`Session::create_identity_from_root`). Nothing is carried from another device per server.
- **Removing a server from a device loses nothing.** Adding it again derives the same account.
- **Servers cannot correlate accounts.** Every derivation includes the server's key. A server key shorter
  than 32 bytes is refused, so a missing key can never quietly give every server the same account.
- **A server's identity key is part of the account.** If a server replaces its identity key, the
  derivation changes and the old account is unreachable from the root alone.

Device signature keys are still random and per device per server; only the user identity key is derived.

**An account taken over with a claim code keeps its old id.** When everything is lost, the server's
owner can let a person's *new* identity take their account over (the server's `reclaim`; see its
`docs/e2ee.md`). That account's id is not the one the new root derives, so
`Session::create_identity_from_root_for(root, server_key, user_id, device_id)` certifies a device for a
given id with the identity key the root derives for that server. Every other device of the person does
the same; the client carries the id in the vault (`accountId`), since it cannot be derived.

## Signing in

There is no password. `Session::sign_auth_challenge(server_key, nonce)` signs, with the device key:

```text
"raindrop/auth/v1\n" | server_key_len: u16 (be) | server_key | nonce
```

Plain Ed25519. The server's own identity key is inside the signed bytes so a challenge relayed from
another server yields a signature that server cannot use. See [Wire contracts](wire-contracts.md#sign-in-signature).

## Recovery

The recovery key is still 24 BIP-39 words (`backup::RecoveryKey`). A `RecoverySeed`
(`HKDF(recovery key, "raindrop/recovery/seed/v1\n")`) is what devices keep of it, so the words need not
stay on the device. From the seed, per server:

- `lookup_id(server_key)` — 32 hex characters (context `raindrop/recovery/lookup/v1\n`), the name the
  sealed root is stored under. A new device holding only the words computes it and asks one server for
  the blob before it has an account. It differs per server.
- `seal_root` / `open_root` — the root sealed under a per-server key (context `raindrop/recovery/seal/v1\n`).

A wrong recovery key, a blob from another server and a damaged blob all fail as `BackupLocked`.

## The vault

`RootSecret::seal_vault(server_key, plaintext)` / `open_vault`. The plaintext is the client's own
encoding (the list of servers, the device roster, pinned identities); the core seals bytes. It is sealed
separately for each server, so two servers' copies share neither key nor ciphertext.

`Session::export_pins` and `import_pins` move pinned identities through the vault. Importing only adds
users this device has not met: a vault can extend trust but can never replace a key already pinned here.

## Sealed formats

All XChaCha20-Poly1305. The associated data is everything before the nonce, followed by the server's
identity key where there is one, so a blob cannot be moved to another server or have its parameters
weakened.

```text
sealed root:  "RDRT" | version: u8 = 1 | nonce: 24 | ciphertext of the 32-byte root
vault:        "RDVT" | version: u8 = 1 | nonce: 24 | ciphertext
PIN lock:     "RDPL" | version: u8 = 1 | memory_kib: u32 | iterations: u32 | parallelism: u32
                     | salt: 16 | nonce: 24 | ciphertext
```

## The app PIN

`root::seal_with_pin` / `open_with_pin`, for a device with no biometric or system credential. Argon2id,
64 MiB and 3 passes by default (`PinCost`): lighter than a backup passphrase because it runs at every
unlock and the blob never leaves the device. On opening, the cost read from the blob must be within
19 MiB–512 MiB, 1–10 passes and 1–8 lanes of parallelism, checked before the KDF runs; anything else is
`Malformed`. A wrong PIN is `BackupLocked`.

## Pairing a device

`pairing.rs`. Once per device, covering every server — unlike device linking, which moved one server's
identity and named a user.

1. The **new** device calls `pairing::begin(device_name, platform)`: an offer (name, platform, a fresh
   X25519 key), its 16-byte commitment, a random 16-byte code secret (`CODE_SECRET_LENGTH`), and the
   exchange secret to hold until the approval arrives. The code secret never goes to the relay.
2. The person carries the pairing code (the relay's id for the offer, the commitment and the code
   secret) to an **existing** device, scanned or typed. `pairing::approve(offer, commitment, code_secret,
   payload)` refuses an offer that does not match the commitment, then seals the payload to the offer's
   key and the code secret.
3. The new device calls `pairing::complete(approval, offer, exchange_secret, code_secret)`. An approval
   that does not open is `Verification`.

The commitment stops a relay from swapping in an offer of its own (new → existing); the code secret
stops it from sealing a root of its own to the offer's key and serving that as the approval
(existing → new), since it holds the offer but not the code.

The payload is the caller's bytes: the root, the recovery seed, the vault contents and the
authenticator secret. The authenticator secret travels **only** this way — never in the vault, where
leaked recovery words would reveal it.

```text
offer:     version: u8 = 1 | name_len: u16 | name | platform_len: u16 | platform | exchange_key: 32
approval:  version: u8 = 2 | sender_key: 32 | nonce: 24 | ciphertext
```

Sealing is X25519 with a fresh sender key, HKDF-SHA256 over the shared secret with the code secret as
salt and `info = "raindrop/device-pairing/v2\n" | offer | sender_key`, then XChaCha20-Poly1305 with the
sender key as associated data. The commitment is the first 16 bytes of
`SHA-256("raindrop/device-pairing/v2\n" | offer)`. An all-zero shared secret is refused. Names and platforms are at most 64 bytes; they
are chosen by the new device and are a label to recognise it by, never a reason to approve.

## What this does not protect against

Every paired device holds the root. A device that is stolen *unlocked* has the identity; revoking it on
the servers stops its sessions but does not take the root back. The remedy is a new root and
re-registration everywhere.
