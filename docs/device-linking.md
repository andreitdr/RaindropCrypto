# Device linking

A user adding a device while another one still works moves their identity secret across without the
server being able to read or substitute it. Code: `link.rs`, and `Session::begin_device_link`,
`approve_device_link` and `complete_device_link`. The server's relay for the offer and approval is
described in its [E2EE doc](../../RaindropServer/docs/e2ee.md#linking-a-new-device).

## The flow

1. **New device** (no identity yet) calls `begin_device_link(user_id, device_id)`. It makes its device
   signature key, a fresh X25519 exchange key and a random 16-byte **code secret**
   (`CODE_SECRET_LENGTH`), stores them as an unfinished link, and returns an **offer** to upload and the
   **commitment** and code secret to put in the link code. The code secret is never uploaded. Starting
   again replaces an unfinished link.
2. The user carries the **link code** (`RDL2-<link id>-<commitment>-<code secret>`, shown as text or a
   QR code) to an **existing device**. The link id comes from the server; the commitment and code secret
   from step 1.
3. **Existing device** fetches the offer and calls `approve_device_link(offer, commitment, code_secret)`.
   It refuses unless:
   - the offer matches the commitment (compared in constant time), so a server that swapped in its own
     keys is caught;
   - the offer is for *this device's own user*;
   - the offered device key is 32 bytes (Ed25519).

   It then certifies the new device key with the identity key and seals the identity secret, the
   certificate and the pins to the offer's X25519 key and the code secret. The result is the
   **approval**.
4. **New device** calls `complete_device_link(approval)`. It opens the approval with its stored exchange
   key and code secret, and checks that the certificate verifies and is about *this device's own offer*
   (same identity key, device key, user id and device id). Only then does it install the pins and the
   identity, and delete the unfinished link. An approval that does not open is `Verification`, and
   leaves the link in progress.

The server never sees anything it could use: the offer is public keys, and the approval is sealed to a
key only the new device holds. Nor can it **substitute** an approval: it holds the offer, so it could
seal an identity, certificate and pins of its own to the offer's key, but the approval key also depends
on the code secret, which only travels in the link code. The commitment protects the new → existing
direction; the code secret protects existing → new.

## The offer and the commitment

`Offer` holds `user_id`, `device_id`, `device_signature_key` and the 32-byte `exchange_key`. The
**commitment** is the first `COMMITMENT_LENGTH` = 16 bytes of `SHA-256("raindrop/device-link/v2\n" ‖
offer)`: 128 bits, which makes finding a second offer with the same commitment infeasible even for a
server that has seen the first.

The link code is the only thing that travels outside the server, and it commits to the whole offer and
carries the code secret. That is what turns "the server relays the offer and the approval" from a trust
assumption into something checked.

## Sealing the approval

`seal_approval` uses an **ephemeral sender key**: X25519 with the offer's exchange key, then
HKDF-SHA256 over the shared secret, then XChaCha20-Poly1305.

| Piece | Detail |
|---|---|
| Key | HKDF-SHA256, salt = the 16-byte code secret, `info = "raindrop/device-link/v2\n" ‖ offer ‖ sender public key`, 32 bytes |
| AEAD | XChaCha20-Poly1305, random 24-byte nonce, associated data = the sender public key |
| Contents | JSON of the certificate, the identity secret and the pins |

Binding the key to the **whole offer** and both public keys means an approval opens only against the
offer it was made for. An all-zero shared secret (a low-order public key) is refused rather than turned
into a key an attacker could predict. The byte layout is in [Wire contracts](wire-contracts.md#device-link).

## State kept between the steps

While a link is in progress the new device keeps `link.offer`, `link.exchange_secret` and
`link.code_secret` in the [local store](local-store.md#the-meta-table), so the process can be restarted
between showing the code and receiving the approval. All three are deleted on completion. A link begun
before the code secret existed has no `link.code_secret` and reports `NotFound`; begin it again.
