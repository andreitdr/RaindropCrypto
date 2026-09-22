# Device linking

A user adding a device while another one still works moves their identity secret across without the
server being able to read or substitute it. Code: `link.rs`, and `Session::begin_device_link`,
`approve_device_link` and `complete_device_link`. The server's relay for the offer and approval is
described in its [E2EE doc](../../RaindropServer/docs/e2ee.md#linking-a-new-device).

## The flow

1. **New device** (no identity yet) calls `begin_device_link(user_id, device_id)`. It makes its device
   signature key and a fresh X25519 exchange key, stores them as an unfinished link, and returns an
   **offer** to upload and the **commitment** to put in the link code. Starting again replaces an
   unfinished link.
2. The user carries the **link code** (`RDL1-<link id>-<commitment>`, shown as text or a QR code) to an
   **existing device**. The link id comes from the server; the commitment from step 1.
3. **Existing device** fetches the offer and calls `approve_device_link(offer, commitment)`. It refuses
   unless:
   - the offer matches the commitment (compared in constant time), so a server that swapped in its own
     keys is caught;
   - the offer is for *this device's own user*;
   - the offered device key is 32 bytes (Ed25519).

   It then certifies the new device key with the identity key and seals the identity secret, the
   certificate and the pins to the offer's X25519 key. The result is the **approval**.
4. **New device** calls `complete_device_link(approval)`. It opens the approval and checks that the
   certificate verifies and is about *this device's own offer* (same identity key, device key, user id
   and device id). Only then does it install the pins and the identity, and delete the unfinished link.

The server never sees anything it could use: the offer is public keys, and the approval is sealed to a
key only the new device holds.

## The offer and the commitment

`Offer` holds `user_id`, `device_id`, `device_signature_key` and the 32-byte `exchange_key`. The
**commitment** is the first `COMMITMENT_LENGTH` = 16 bytes of `SHA-256("raindrop/device-link/v1\n" ‖
offer)`: 128 bits, which makes finding a second offer with the same commitment infeasible even for a
server that has seen the first.

The link code is the only thing that travels outside the server, and it commits to the whole offer. That
is what turns "the server relays the offer" from a trust assumption into something checked.

## Sealing the approval

`seal_approval` uses an **ephemeral sender key**: X25519 with the offer's exchange key, then
HKDF-SHA256 over the shared secret, then XChaCha20-Poly1305.

| Piece | Detail |
|---|---|
| Key | HKDF-SHA256, no salt, `info = "raindrop/device-link/v1\n" ‖ offer ‖ sender public key`, 32 bytes |
| AEAD | XChaCha20-Poly1305, random 24-byte nonce, associated data = the sender public key |
| Contents | JSON of the certificate, the identity secret and the pins |

Binding the key to the **whole offer** and both public keys means an approval opens only against the
offer it was made for. An all-zero shared secret (a low-order public key) is refused rather than turned
into a key an attacker could predict. The byte layout is in [Wire contracts](wire-contracts.md#device-link).

## State kept between the steps

While a link is in progress the new device keeps `link.offer` and `link.exchange_secret` in the
[local store](local-store.md#the-meta-table), so the process can be restarted between showing the code
and receiving the approval. Both are deleted on completion.
