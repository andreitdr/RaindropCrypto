# Wire contracts

Formats this crate defines that the [client](../../RaindropClient/docs/crypto.md) and
[server](../../RaindropServer/docs/e2ee.md) also read or produce. There is no other implementation to
check compatibility against, so a change here has to be made in all three places in the same change —
this crate, the C# that parses or validates it, and any Dart that assumes its shape.

**How they travel.** Client and server talk gRPC, in messages defined by
[RaindropProto](../../RaindropProto/README.md). Every format below rides inside those messages as an
opaque protobuf `bytes` field, exactly as this crate produced it; nothing is re-encoded on the way, so
the transport has no say in any of these layouts. The plaintext *inside* an encrypted message (text,
file keys and names) is the client's `MessagePayload`, protobuf as well (RaindropProto's
`payload.proto`); this crate encrypts it without reading it.

## Device certificate

Defined in `identity.rs` (`DeviceCertificate::to_bytes` / `from_bytes` / `signed_bytes`); parsed on the
server by `RaindropServer/E2ee/DeviceCertificate.cs`, whose doc comment mirrors this layout. Full detail:
[Identity & trust](identity-and-trust.md#devicecertificate).

```text
version: u8 = 1 | user_id | device_id | device_signature_key | user_identity_key
| created_at_unix: i64 (be) | signature
```

Every non-fixed field is length-prefixed: `u16` big-endian length, then that many bytes. A field longer than
65,535 bytes cannot be encoded: `to_bytes` (and `certify_device`, and `Offer::to_bytes` for pairing and
linking) return `Malformed` rather than truncating the length. `user_id` and
`device_id` are UTF-8 text — UUIDs in practice, but the *exact text the client wrote* is what is signed
and what the server compares, never a re-formatted `Guid`, because re-formatting (case, hyphenation)
would break the signature. `signature` is Ed25519 by `user_identity_key` over everything up to
`created_at_unix`, prefixed with the context string `"raindrop/device-certificate/v1\n"` and the version
byte. The server's `DeviceCertificate.Parse` enforces the same length prefixes and the same 1024-byte
ceiling as an obviously-malformed-input guard, and checks the two key fields are 32 bytes (Ed25519).

**If this changes:** update `identity.rs`, `RaindropServer/E2ee/DeviceCertificate.cs`, and the doc
comments in both.

## Session-binding signature

Context string `"raindrop/session-binding/v1\n"`, prefixed to the server's challenge nonce before the
device signs it (`Session::sign_session_challenge`). Plain Ed25519, not wrapped in any envelope. The
server issues the nonce (`POST /api/e2ee/session/challenge`, 32 bytes, 2 minutes, single use) and checks
the signature against the device key in the stored certificate
(`POST /api/e2ee/session/bind`). See [Identity & trust](identity-and-trust.md#session-binding).

## Sign-in signature

Context string `"raindrop/auth/v1\n"`, then the server's identity key length-prefixed (`u16` big-endian),
then the server's challenge nonce; the device signs the whole with its device key
(`Session::sign_auth_challenge`). Plain Ed25519. The server must build the same bytes from **its own**
identity key, exactly as it publishes it in `GetServerInfo`, and its own nonce
(`RaindropServer/E2ee/DeviceAuthService.SignedBytes`). The server's test suite verifies a fixture this crate writes
(`print_auth_fixture` in `tests/session.rs` → `RaindropServer.Tests/Fixtures/auth_signature.hex`), so a
change to either side fails there; regenerate the fixture when the format changes on purpose.

**If this changes:** update `session.rs`, the server's verifier, and both docs.

## Sealed root, vault and pairing blobs

Defined in `root.rs` and `pairing.rs`; layouts in [Root identity](root-identity.md#sealed-formats). The
server stores and relays them as opaque bytes and never parses them. The sealed root is stored under
`RecoverySeed::lookup_id` (32 lowercase hex characters), which the server treats as an opaque name.

The pairing approval is version 2 (`"raindrop/device-pairing/v2\n"`): its key is salted with a 16-byte
code secret that travels only in the pairing code (`RDP2-<pairing id>-<commitment>-<code secret>`, both
in base32), never to the server, so a relay cannot seal an approval of its own. The server sees only the
pairing id; nothing it stores or checks depends on the code's layout.

## Message attestation

A device signs every message it sends so a recipient can later prove to moderators who wrote it
(`Session::sign_message_attestation`). The caller passes the canonical bytes (the client's
`MessagePayload.attestationBytes`, recomputed by the server's `MessageReportService.Canonical`), and the
core prefixes the context. `"raindrop/message-attestation/v1\n"` covers the channel, client message id,
send time, type and body. `"raindrop/message-attestation/v2\n"` (`sign_message_attestation_v2`) is for a
message that carries files: the same fields, then a 4-byte count and each file's id and 32-byte
ciphertext hash, so a reporter cannot pair the words with another file. The two contexts never verify
for each other.

**If this changes:** a new context, the client's `attestationBytes`, and the server's `Canonical` /
`CanonicalWithFiles` (both sides test against the same golden vector).

## Device link

Two formats, both in `link.rs`:

- **Offer** (`Offer::to_bytes` / `from_bytes`): `version: u8 = 1 | user_id | device_id |
  device_signature_key | exchange_key: 32 bytes`, same length-prefix convention as the certificate.
  Uploaded as-is; the server stores and relays it without reading it as anything but bytes
  (`POST /api/e2ee/device-link/start` / `offer`).
- **Link code**: `RDL2-<link id>-<commitment>-<code secret>`, where `<link id>` comes from the server,
  `<commitment>` is `link::commitment(offer)`: the first 16 bytes of `SHA-256("raindrop/device-link/v2\n"
  ‖ offer)`, and `<code secret>` is 16 random bytes from `begin_device_link` that are never uploaded.
  Both are base32. The prefix `RDL2` is the only part either side parses as a literal; the rest is
  opaque to the server, which only ever receives the link id.
- **Approval** (`seal_approval` / `open_approval`): `version: u8 = 2 | sender_public_key: 32 bytes |
  nonce: 24 bytes | XChaCha20-Poly1305 ciphertext`, its key salted with the code secret. The server
  stores and relays it as an opaque blob (`POST /api/e2ee/device-link/approve` / `approval`), up to
  8 KiB; the size is unchanged from version 1.

Full detail: [Device linking](device-linking.md).

**If this changes:** update `link.rs`, the server's `IDeviceLinkRelay` size limits if they depend on the
format's size, and both e2ee docs' descriptions of the flow.

## Key backup blob

`backup.rs`. Stored by the server as an opaque blob up to 64 KiB (`POST /api/e2ee/backup/put`), read back
to any password session (`GET /api/e2ee/backup`) — the server never opens it. Full layout in
[Key backup](key-backup.md#blob-layout).

**If this changes:** update `backup.rs` and the size limit in `E2eeOptions` on the server if the new
layout can exceed it.

## Attachment

`attachment.rs`, format `raindrop/attachment/v1`: a version byte, a 19-byte nonce prefix, then 64 KiB
XChaCha20-Poly1305 segments. Full layout in [Attachments](attachments.md#format-raindropattachmentv1).
The server never decrypts it, but it relies on the **length formula**
`ciphertext = 20 + plaintext + 16 × max(1, ⌈plaintext / 65536⌉)` to enforce the owner's size limits, and
on the SHA-256 of the whole ciphertext to check an upload is complete
(`RaindropServer/Attachments/AttachmentFormat.cs`, [server doc](../../RaindropServer/docs/attachments.md)).

**If this changes:** a new version byte and context string, `AttachmentFormat` on the server, and the
client's upload code, which declares the ciphertext length before uploading.

## MLS group id

Not a byte format this crate parses, but a convention it depends on: **a channel's MLS group id is the
channel's UUID as 16 big-endian bytes**, followed — for any generation of the channel's group after 0 — by
the generation as 8 big-endian bytes (24 bytes in all). The client computes it with
`groupIdForChannel(channelId, generation)`, the server with `MlsFraming.GroupIdFor(channelId, generation)`
(`Guid.ToByteArray(bigEndian: true)` for the first 16), and the server checks every commit, group info and
encrypted message against the channel's current generation. Both sides' tests pin the same vector
(`00112233-4455-6677-8899-aabbccddeeff`, generation `0x0102030405`).
`Session` treats group ids as opaque bytes and does not enforce this — the convention lives in the
caller, so a change here is a client-only change, but any two sides that compute a group id independently
(the app on two platforms, say) must compute it identically.

## Event payloads carrying certificates

The server's `e2ee.device.added` / `e2ee.device.revoked` events carry the raw certificate bytes
(`DeviceEvent(UserId, DeviceId, Certificate)`), which any client decodes with
`DeviceCertificate::from_bytes` and re-verifies itself — the server's own parse is not trusted for this,
only used to decide what to store and relay. See the server's
[E2EE doc](../../RaindropServer/docs/e2ee.md#events).
