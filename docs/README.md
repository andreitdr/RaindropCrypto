# RaindropCrypto documentation

RaindropCrypto is the end-to-end encryption core of Raindrop, a decentralised, self-hosted chat
platform. It is Rust, built on **MLS** (RFC 9420) through OpenMLS, and it runs entirely on clients: the
[server](../../RaindropServer/docs/README.md) never holds a private key and never links this code.

It also carries the client's **camera-effects** core ([Camera effects](video-effects.md)) — unrelated
to encryption, but Rust that has to reach all five of the client's targets, which is exactly what this
workspace's build already does.

This wiki documents the feature set as it stands today. Each file covers one area; start with
[Architecture overview](architecture-overview.md) if you're new to the codebase, and
[Roadmap](roadmap.md) for what is and is not built yet.

## The three Raindrop projects

Raindrop is three repositories, checked out side by side in one folder:

| Project | What it is | Its docs |
|---|---|---|
| **RaindropCrypto** (this one) | The end-to-end encryption core: Rust, MLS over OpenMLS, no networking | you are here |
| [RaindropServer](../../RaindropServer/docs/README.md) | The self-hosted .NET backend. Carries bytes it cannot read: ciphertext, group state, sealed backups, device-link blobs | [docs](../../RaindropServer/docs/README.md) · [its E2EE side](../../RaindropServer/docs/e2ee.md) |
| [RaindropClient](../../RaindropClient/docs/README.md) | The Flutter app. The only caller of this code — it compiles `raindrop_crypto_ffi` into the app | [docs](../../RaindropClient/docs/README.md) · [its crypto doc](../../RaindropClient/docs/crypto.md) |

What binds the three together is not code but byte formats: everything in
[Wire contracts](wire-contracts.md) has to change in all three at once.

## Contents

| Doc | Covers |
|---|---|
| [Architecture overview](architecture-overview.md) | The two crates, every module, how a `Session` is used, what the core does and does not do |
| [Identity & trust](identity-and-trust.md) | User identity keys, device certificates, credential validation and pinning, safety numbers, session binding |
| [Groups & messages](groups-and-messages.md) | MLS groups, key packages, commits and epochs, joining, encrypting and receiving, the message cache, exported secrets |
| [Key backup](key-backup.md) | The recovery key, the Argon2id passphrase path, the sealed blob format |
| [Device linking](device-linking.md) | Moving an identity onto a new device through a server that cannot read or substitute it |
| [Root identity, vault & pairing](root-identity.md) | The one root secret, per-server accounts derived from it, passwordless sign-in signatures, the recovery seed, the vault, the app PIN, pairing a device |
| [Attachments](attachments.md) | Files: the per-file key, the chunked `raindrop/attachment/v1` format, the length contract with the server |
| [Camera effects](video-effects.md) | Background blur and background replacement on a call's camera: the I420 frame boundary, the two clocks, the mask, the degradation ladder, the segmentation seam |
| [Local store](local-store.md) | The SQLCipher database: what it holds, the tables, how it is opened |
| [Flutter bridge](flutter-bridge.md) | `raindrop_crypto_ffi`, the flat bridge types, error kinds, codegen, the version pin, the build glue |
| [Wire contracts](wire-contracts.md) | Every byte format the client and server also read, and what has to change together |
| [Testing & building](testing.md) | Toolchain, commands, what the tests cover |
| [CI & releases](ci-and-releases.md) | The GitHub Actions workflows, and why the client does not use their artefacts |
| [Roadmap](roadmap.md) | Everything implemented today, everything that is not, and what is deliberately not planned |

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
  pinning, safety numbers, session-binding signatures, message attestations, device linking, the
  recovery-key and passphrase backup, the encrypted store with its message cache, MLS groups (add,
  remove, self-update, welcome, external join, commit merge/discard), message encrypt/decrypt, the
  chunked attachment format, and exported secrets for call keys.
- **In use end to end:** the client drives each channel's MLS group through the server's
  [delivery service](../../RaindropServer/docs/e2ee.md#the-delivery-service), so encrypted text
  messages, encrypted files and encrypted call media all reach users today. Nothing in this core is
  built but unused.
- **What's not implemented yet:** injecting a custom `CredentialValidator` into a `Session` (see
  [Identity & trust](identity-and-trust.md#the-validator-seam)), a second ciphersuite, scheduled key
  rotation, and message-cache retention. The full list is in [Roadmap](roadmap.md).

## Keeping this wiki current

**Update the relevant file(s) here whenever a feature changes or a new one is added** — a new `Session`
method, a changed byte format, a new error kind, a new bridge function. Treat this as part of the
change, not a follow-up: a docs folder that drifts from the code is worse than no docs folder, because
it actively misleads. When a change doesn't fit any existing file, add a new one and link it from the
table above.

If a change touches a format in [Wire contracts](wire-contracts.md), also update the server's
[E2EE doc](../../RaindropServer/docs/e2ee.md) and the client's [crypto doc](../../RaindropClient/docs/crypto.md).

**[Roadmap](roadmap.md) is part of that.** Anything that moves between implemented and not goes there
in the same change, and a gap that crosses a project boundary is recorded in the other project's
roadmap too ([RaindropServer](../../RaindropServer/docs/roadmap.md) ·
[RaindropClient](../../RaindropClient/docs/roadmap.md)).
