# Dependency advisories

What the RustSec / OSV databases report against `Cargo.lock` and has **not** been fixed, because no
fix is reachable without an upstream release. Everything else they reported was fixed by updating.
Re-check this list on every dependency update, and delete an entry as soon as its fix is reachable.

Last audited 2026-11-15 (every locked crate against [OSV.dev](https://osv.dev), which mirrors RustSec).

| Advisory | Crate (locked) | Fixed in | Why it is still here |
|---|---|---|---|
| [RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459) | `libsqlite3-sys` 0.35.0 | 0.39.0 (`rusqlite` 0.41) | `openmls_sqlite_storage` 0.3.0, the latest release, requires `rusqlite ^0.37`, and only one `libsqlite3-sys` may be linked. The bundled SQLCipher is SQLite 3.46.1; the bug is SQLite before 3.54.0 returning stale page-cache memory when it opens a database together with a crafted `-wal` file of a different page size. It needs someone able to plant both files in the app's own data folder. |
| [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387) | `crypto-bigint` 0.5.5 | 0.7.6 | Pulled in by `p256`/`p384` 0.13 through `openmls_rust_crypto` and `openmls_basic_credential` 0.6.0 (the latest), which need `elliptic-curve` 0.13. The timing issues are in the NIST-curve arithmetic; `CIPHERSUITE` is X25519 + Ed25519, so this core never signs or derives with those curves. |
| [RUSTSEC-2026-0330](https://rustsec.org/advisories/RUSTSEC-2026-0330), [-0331](https://rustsec.org/advisories/RUSTSEC-2026-0331) | `libcrux-kem` 0.0.9 | 0.0.10 | In `Cargo.lock` only: it belongs to `hpke-rs-libcrux`, an optional backend of `hpke-rs` that nothing enables, so it is never compiled (`cargo tree -i libcrux-kem --target all` prints nothing). |
| [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173) (unmaintained) | `proc-macro-error2` 2.0.1 | — | A compile-time proc-macro under `hax-lib`, used by the `libcrux` crates `hpke-rs` depends on. A notice that it is unmaintained, not a vulnerability. |

The way out of the first three is the next OpenMLS release line (`openmls_sqlite_storage` on a newer
`rusqlite`, `openmls_rust_crypto` on `p256` 0.14 / `hpke-rs` 0.8).
