# RaindropCrypto documentation

RaindropCrypto is the end-to-end encryption core of Raindrop, a decentralised, self-hosted chat
platform. It is Rust, built on **MLS** (RFC 9420) through OpenMLS, and it runs entirely on clients: the
[server](../../RaindropServer/docs/README.md) never holds a private key and never links this code.

This wiki documents the feature set as it stands today. Each file covers one area; start with
[Architecture overview](architecture-overview.md) if you're new to the codebase.

## Contents

| Doc | Covers |
|---|---|
| [Architecture overview](architecture-overview.md) | The two crates, every module, how a `Session` is used, what the core does and does not do |
| [Identity & trust](identity-and-trust.md) | User identity keys, device certificates, credential validation and pinning, safety numbers, session binding |
| [Groups & messages](groups-and-messages.md) | MLS groups, key packages, commits and epochs, joining, encrypting and receiving, the message cache, exported secrets |
| [Key backup](key-backup.md) | The recovery key, the Argon2id passphrase path, the sealed blob format |
| [Device linking](device-linking.md) | Moving an identity onto a new device through a server that cannot read or substitute it |
| [Local store](local-store.md) | The SQLCipher database: what it holds, the tables, how it is opened |
| [Flutter bridge](flutter-bridge.md) | `raindrop_crypto_ffi`, the flat bridge types, error kinds, codegen, the version pin, the build glue |
| [Wire contracts](wire-contracts.md) | Every byte format the client and server also read, and what has to change together |
| [Testing & building](testing.md) | Toolchain, commands, what the tests cover |

## Quick facts

- **Stack:** Rust (edition 2024), a Cargo workspace. OpenMLS 0.9, RustCrypto primitives, SQLCipher via
  `rusqlite`, flutter_rust_bridge 2.13.0.
- **Ciphersuite:** `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, in the constant `CIPHERSUITE`.
- **Shape:** one `Session` per server profile on a device; one MLS group per channel, whose group id is
  the channel's UUID.
- **No networking.** The core produces and consumes bytes; the caller delivers them.
- **Who uses it:** [RaindropClient](../../RaindropClient/docs/crypto.md) compiles the bridge crate into
  the app. [RaindropServer](../../RaindropServer/docs/e2ee.md) reads the formats in
  [Wire contracts](wire-contracts.md) but has none of this code.
- **What's implemented:** device identities and certificates, credential validation with identity
  pinning, safety numbers, session-binding signatures, device linking, the recovery-key and passphrase
  backup, the encrypted store with its message cache, MLS groups (add, remove, self-update, welcome,
  external join, commit merge/discard), message encrypt/decrypt, and exported secrets for call keys. The
  server's [MLS delivery service](../../RaindropServer/docs/e2ee.md#the-delivery-service) is also
  implemented and the client's `E2eeApi` wrapper is wired and tested against it.
- **What's not implemented yet:** the app does not yet drive a channel's group through that delivery
  service — nothing calls `create_group`/`add_members`/`encrypt` for an actual channel — so encrypted
  text messages and calls do not reach users yet even though every piece they need is built and tested.
  A custom `CredentialValidator` cannot yet be injected into a `Session` (see
  [Identity & trust](identity-and-trust.md#the-validator-seam)).

## Keeping this wiki current

**Update the relevant file(s) here whenever a feature changes or a new one is added** — a new `Session`
method, a changed byte format, a new error kind, a new bridge function. Treat this as part of the
change, not a follow-up: a docs folder that drifts from the code is worse than no docs folder, because
it actively misleads. When a change doesn't fit any existing file, add a new one and link it from the
table above.

If a change touches a format in [Wire contracts](wire-contracts.md), also update the server's
[E2EE doc](../../RaindropServer/docs/e2ee.md) and the client's [crypto doc](../../RaindropClient/docs/crypto.md).
