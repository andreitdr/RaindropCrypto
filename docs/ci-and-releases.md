# CI & releases

Two GitHub Actions workflows live in [`.github/workflows/`](../.github/workflows).

## `ci.yml` — build and test

Runs on every push to `main`, and as the first stage of `release.yml` (`workflow_call`). A newer push
cancels a run still in progress. Both jobs use `dtolnay/rust-toolchain@stable` and
`Swatinem/rust-cache@v2`.

| Job | Does |
|---|---|
| `build` | `cargo build --workspace --all-targets --locked` |
| `test` | after `build`: `cargo test --workspace --locked` |

`--locked` means `Cargo.lock` is authoritative: a dependency bump has to be committed, it cannot
happen on the runner. Both jobs run on `ubuntu-latest` only — the crate is built for every real
target by the client's own build (cargokit), so CI's job here is correctness, not coverage of
platforms. What the tests cover is in [Testing & building](testing.md).

Clippy and `cargo fmt` are **not** run in CI; run them before pushing:

```bash
cargo clippy --all-targets && cargo fmt --all
```

## `release.yml` — package and publish

Triggered by a pushed version tag matching `v[0-9]+.[0-9]+.[0-9]+`.

1. **`ci`** — reruns `ci.yml` against the tagged commit.
2. **`package`** — on `ubuntu-latest` and `macos-latest`: `cargo build --release --locked -p
   raindrop_crypto_ffi`, then tars whatever of `libraindrop_crypto_ffi.{so,dylib,a}` exists into
   `RaindropCrypto-<version>-<linux|macos>.tar.gz`.
3. **`release`** — `gh release create <tag> dist/* --verify-tag --generate-notes`.

These artefacts are a convenience for anything that wants a prebuilt library. **The Flutter client
does not use them**: it compiles this workspace from source through
[`native/raindrop_crypto_builder`](../../RaindropClient/docs/crypto.md#building), from the sibling
checkout — on CI, from this repository's current `main` rather than a matching tag.

Each project is tagged in its own repository, and the workflow comments point at a `release.sh` in
the folder that holds all three checkouts. That script is not part of this repository — tagging by
hand (`git tag vX.Y.Z && git push origin vX.Y.Z`) triggers the same workflow.

## What CI does not do

- No crates.io publish: both crates are `publish = false`.
- No Windows or Android artefacts (see [Roadmap](roadmap.md)).
- No clippy, rustfmt, audit or coverage gate.
- No PR trigger: `push` to `main` only.

## Related

- [Testing & building](testing.md) — the toolchain, the commands, what the tests cover.
- The client's [crypto doc](../../RaindropClient/docs/crypto.md) — how the app compiles this crate,
  and the `flutter_rust_bridge` version pin the three places must agree on.
- The other projects' pipelines: [RaindropServer](../../RaindropServer/docs/ci-and-releases.md),
  [RaindropClient](../../RaindropClient/docs/ci-and-releases.md).
