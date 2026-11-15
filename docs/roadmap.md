# Roadmap

What RaindropCrypto does today, and what it does not do yet. This file is the honest inventory for
the **crypto core**; the other two projects keep their own, and nothing here is visible to a user
until the client drives it and the server carries it:

- [RaindropServer roadmap](../../RaindropServer/docs/roadmap.md) — the .NET backend.
- [RaindropClient roadmap](../../RaindropClient/docs/roadmap.md) — the Flutter app.

**Keep this honest.** When something here ships, move it from *Not implemented yet* into
*Implemented* in the same change that ships it, and update the doc it points at.

## Implemented

| Area | What works | Doc |
|---|---|---|
| Session | One `Session` per server profile on a device, opened over a SQLCipher store with a caller-held 32-byte key; one identity per store, enforced | [Architecture](architecture-overview.md) |
| Identity | Ed25519 user identity keys, device certificates signed by them, `safety_number` (60 digits) | [Identity & trust](identity-and-trust.md) |
| Trust | `PinnedIdentityValidator`: every credential in every group is verified and pinned trust-on-first-use, `IdentityChanged` surfaced as a user decision, `accept_changed_identity` / `mark_verified` | [Identity & trust](identity-and-trust.md) |
| Session binding | `sign_session_challenge`, so a server session can be tied to a device key | [Identity & trust](identity-and-trust.md) |
| Camera effects | The frame boundary (I420, stride-safe), background blur, background replacement, mask stretch and temporal smoothing, the two-clock pipeline and the degradation ladder, and MediaPipe's Selfie Segmentation run by `tract` — model committed, with `models/convert.py` to rebuild and re-verify it | [Camera effects](video-effects.md) |
| Camera effects, reached | Three surfaces: flutter_rust_bridge for control, one `extern "C"` function Apple's capture pipeline calls by address, and a JNI entry point for Android, which cannot be handed one | [Camera effects](video-effects.md#the-three-surfaces) |
| Attestations | `sign_message_attestation` (v1) and `sign_message_attestation_v2` for a message carrying files | [Wire contracts](wire-contracts.md#message-attestation) |
| Groups | `create_group`, `add_members`, `remove_members`, `self_update`, `join_from_welcome`, `join_by_external_commit`, `group_info`, `members`, `epoch`, `merge_pending_commit` / `discard_pending_commit` (commit races), `delete_group` | [Groups & messages](groups-and-messages.md) |
| Key packages | `generate_key_packages`, one-time and last-resort, `MLSMessage`-wrapped as the server requires | [Groups & messages](groups-and-messages.md) |
| Messages | `encrypt`, `process`, `receive_message`, `remember_sent`, and the decrypted message cache that makes history readable after the epoch's keys are gone | [Groups & messages](groups-and-messages.md), [Local store](local-store.md) |
| Call keys | `export_secret`, which the client turns into SFrame media keys for a voice channel's call | [Groups & messages](groups-and-messages.md) |
| Key backup | 24-word recovery key, or a passphrase via Argon2id; sealed blob the server stores and cannot read; `backup_needs_passphrase` | [Key backup](key-backup.md) |
| Device linking | `begin_device_link` / `approve_device_link` / `complete_device_link`: X25519 + HKDF + XChaCha20-Poly1305, bound to the link code's commitment so the server cannot substitute keys | [Device linking](device-linking.md) |
| Root identity | `RootSecret` and the per-server account derived from it, `create_identity_from_root`, the `sign_auth_challenge` sign-in signature, `RecoverySeed` (lookup id, sealed root), the per-server sealed vault, pin export/import, the Argon2id app PIN lock, and `pairing` (offer, commitment, sealed approval). In use by the server and the client | [Root identity](root-identity.md) |
| Files | The chunked `raindrop/attachment/v1` format, per-file keys, file-to-file and in-memory paths, `ciphertext_length` as the exact contract the server enforces sizes with | [Attachments](attachments.md) |
| Local store | SQLCipher (CommonCrypto on Apple targets, vendored OpenSSL elsewhere), holding keys, pins, OpenMLS state and the message cache | [Local store](local-store.md) |
| Flutter bridge | `raindrop_crypto_ffi` over flutter_rust_bridge 2.13.0, flat bridge types with a `kind` enum (no `freezed`, no `build_runner`), `CryptoFailureKind` error mapping | [Flutter bridge](flutter-bridge.md) |
| Tests | Unit tests plus multi-device integration scenarios: adds, external joins, removals, commit races, restarts, restore from backup, an impostor refused | [Testing & building](testing.md) |
| CI | Build + test on every push to `main`, release libraries packaged on a version tag | [CI & releases](ci-and-releases.md) |

Everything above is in use end to end today, except device linking and the per-server key backup, which the root identity replaced and nothing calls any more: the client drives each channel's group through the
server's delivery service, so encrypted text messages and encrypted calls reach users. See
[RaindropClient's crypto doc](../../RaindropClient/docs/crypto.md).

## Not implemented yet

- **Injecting a `CredentialValidator` into a `Session`.** The trait is the seam and
  `PinnedIdentityValidator` is built internally by `Session::validator`, so a plugin cannot supply
  stricter rules yet. [Identity & trust](identity-and-trust.md#the-validator-seam)
- **A second ciphersuite.** `CIPHERSUITE` is one constant
  (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`); a post-quantum or alternative suite would be a
  group parameter, with every group's suite recorded and negotiated.
- **Message franking / deniability work beyond the attestation.** The current attestation lets a
  reporter prove what an author wrote; nothing limits that to the reporter's own view.
- **Automatic key rotation on a schedule.** `self_update` exists and the client calls it when
  membership changes; nothing rotates on a timer or after N messages.
- **Pruning the message cache.** `forget_message` removes one entry; there is no retention policy,
  size cap or re-encryption of the cache.
- **Streaming decryption of a message body.** Messages are whole `Vec<u8>` buffers; only files are
  streamed chunk by chunk.
- **A C or C# binding.** The only binding is the Flutter one. The server deliberately needs none —
  it parses certificates and MLS framing itself from the formats in
  [Wire contracts](wire-contracts.md).
- **Published crates.** Both crates are `publish = false` and versioned `0.1.0`; releases ship built
  libraries, not a registry package. [CI & releases](ci-and-releases.md)
- **Windows and Android release artefacts.** `release.yml` packages Linux and macOS libraries only;
  the client builds the crate itself for every platform it targets, so these are a convenience, not a
  dependency.

## Deliberately not planned

- **Networking.** The core produces and consumes bytes; the caller delivers them. This is what keeps
  the server unable to hold a key and the client free to choose its transport.
- **Holding the store key.** The client keeps the 32-byte database key in the platform keystore and
  passes it in. The core never chooses, derives or stores it.
- **Knowing a message's format.** A payload is opaque bytes; the client owns
  [its structure](../../RaindropClient/docs/messages-chat.md).
