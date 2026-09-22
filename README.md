# RaindropCrypto

Raindrop's end-to-end encryption core, in Rust. It is kept in its own folder, apart from the Flutter
client (`../RaindropClient`) and the .NET server (`../RaindropServer`).

| Crate | Role |
|---|---|
| `crates/raindrop_crypto` | The core. `Session` is one device's state on one server. It covers MLS groups (OpenMLS, ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`), user identity keys and device certificates, credential validation with identity pinning, session-binding signatures, device linking (`link.rs`: X25519 + HKDF + XChaCha20-Poly1305, bound to a link-code commitment), the recovery-key / Argon2id key backup, and a SQLCipher-encrypted local store that includes the decrypted message cache. It does no networking. |
| `crates/raindrop_crypto_ffi` | The flutter_rust_bridge API (`src/api/`) over the core. `src/frb_generated.rs` is generated. |

## Commands

Homebrew's `rustup` is keg-only, so put it on `PATH` first:

```bash
export PATH=/opt/homebrew/opt/rustup/bin:$PATH
```

```bash
cargo test                           # unit + multi-device integration tests
cargo clippy --all-targets
cargo fmt --all
cargo build -p raindrop_crypto_ffi   # the library the Dart bridge test loads
```

Regenerate the Dart bindings after changing `raindrop_crypto_ffi/src/api/`. Run this from
`RaindropClient/`, which holds `flutter_rust_bridge.yaml`:

```bash
flutter_rust_bridge_codegen generate
```

The Flutter app builds this crate by itself through `RaindropClient/native/raindrop_crypto_builder`
(cargokit). See `RaindropClient/docs/crypto.md`.

## Notes

- **SQLCipher's crypto library.** It uses CommonCrypto on Apple targets and a vendored OpenSSL
  elsewhere, selected in `crates/raindrop_crypto/Cargo.toml`. rusqlite stays on the same major
  version as `openmls_sqlite_storage`, so both use the one SQLCipher build.
- **Extension point.** `validation::CredentialValidator` decides whether a group member is who they
  claim to be. The default is `PinnedIdentityValidator`, and a plugin can supply stricter rules.
