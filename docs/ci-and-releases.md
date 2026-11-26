# CI & releases

Two GitHub Actions workflows live in [`.github/workflows/`](../.github/workflows).

## `ci.yml` — build and test

Runs on every push to `main`, and as the first stage of `release.yml` (`workflow_call`). A newer push
cancels a run still in progress. Both jobs use `dtolnay/rust-toolchain@stable` and
`Swatinem/rust-cache@v2`.

| Job | Does |
|---|---|
| `build` | `cargo build --workspace --all-targets --locked` on `ubuntu-latest`, `macos-latest` and `windows-latest` (`fail-fast: false`; Windows gets Strawberry Perl, NASM and a short `CARGO_TARGET_DIR` for the vendored OpenSSL) |
| `test` | after `build`: `cargo test --workspace --locked` |

`--locked` means `Cargo.lock` is authoritative: a dependency bump has to be committed, it cannot
happen on the runner. `test` runs on `ubuntu-latest` only. Android and iOS are not built here — the
client's CI compiles this workspace for both through cargokit, with the same lints. What the tests
cover is in [Testing & building](testing.md).

**Warnings are errors.** `Cargo.toml`'s `[workspace.lints.rust]` sets `warnings = "deny"`, and every
crate opts in with `[lints] workspace = true`, so a warning fails `cargo build` locally, on every CI
platform, and inside the client's cargokit build (crates.io dependencies are exempt: cargo caps their
lints). A failing `build` stops `release.yml`, so **no release is published while any platform has a
compilation error or a warning**. Fix the warning; do not `#[allow]` it to get a build through unless
the code is right and the lint is wrong, and then say why in a comment next to the `allow`.

Clippy and `cargo fmt` are **not** run in CI; run them before pushing:

```bash
cargo clippy --all-targets && cargo fmt --all
```

## `release.yml` — package and publish

Triggered by a pushed version tag matching `v[0-9]+.[0-9]+.[0-9]+`.

1. **`ci`** — reruns `ci.yml` against the tagged commit; any compilation error or warning on any
   platform stops the release here.
2. **`package`** — on `ubuntu-latest` and `macos-latest`: `cargo build --release --locked -p
   raindrop_crypto_ffi`, then tars whatever of `libraindrop_crypto_ffi.{so,dylib,a}` exists into
   `RaindropCrypto-<version>-<linux|macos>.tar.gz`.
3. **`release`** — reads the changelog from the annotated tag (its message minus the subject line,
   written there by `release.sh`) and runs `gh release create <tag> dist/* --verify-tag
   --notes-file notes.md`, so the changelog becomes the release notes. A lightweight tag pushed by
   hand carries none, and the release falls back to `--generate-notes`.

These artefacts are a convenience for anything that wants a prebuilt library. **The Flutter client
does not use them**: it compiles this workspace from source through
[`native/raindrop_crypto_builder`](../../RaindropClient/docs/crypto.md#building), from the sibling
checkout — on CI, from this repository's current `main` rather than a matching tag.

Each project is tagged in its own repository, and the workflow comments point at a `release.sh` in
the folder that holds all three checkouts. That script is not part of this repository. Every release
it makes carries a changelog: drafted from the commit subjects since the previous tag (editable before
tagging) or taken from `--notes-dir DIR/<Repo>.md`. Tagging by hand
(`git tag vX.Y.Z.T && git push origin vX.Y.Z.T`) triggers the same workflow; use an annotated tag
(`git tag -a vX.Y.Z.T --cleanup=verbatim -F notes`) to keep the changelog.

Versions are **X.Y.Z.T**: major (still 0), minor (what a release was before this scheme), update (an
update of the minor version) and hotfix (quick, easy bug fixes only); `release.sh major|minor|update|hotfix`
raises one and resets the ones after it. The releases before were tagged `vA.B.C` and count as
`0.A.B.C`, so the first new one after `v2.2.1` is the hotfix `v0.2.2.2`.

## What CI does not do

- No crates.io publish: both crates are `publish = false`.
- No Windows or Android artefacts (see [Roadmap](roadmap.md)).
- No clippy, rustfmt, audit or coverage gate (compiler warnings *are* a gate, see above).
- No PR trigger: `push` to `main` only.

## Related

- [Testing & building](testing.md) — the toolchain, the commands, what the tests cover.
- The client's [crypto doc](../../RaindropClient/docs/crypto.md) — how the app compiles this crate,
  and the `flutter_rust_bridge` version pin the three places must agree on.
- The other projects' pipelines: [RaindropServer](../../RaindropServer/docs/ci-and-releases.md),
  [RaindropClient](../../RaindropClient/docs/ci-and-releases.md).
