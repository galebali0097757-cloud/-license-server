# r93 initialization program delivery

An r93 client calls `POST /v1/license/verify` with its license key, device ID,
`protocol: "r93"`, pinned build ID and a fresh 32-byte hexadecimal nonce.
Existing license status, expiration, device binding and maintenance checks
apply before delivery. Legacy r88 responses retain their existing format.

The response adds `engine` (hexadecimal program bytes) and `engine_sha256`.
The engine is encrypted at rest in the Worker source and decrypted using the
existing `REAPER_SIGNING_KEY_PKCS8` secret. No plaintext engine file is deployed
as a public asset. The code is a bounded initialization bytecode program for an
interpreter in the matching client, rather than downloaded native executable
memory.

The signed message is 212 bytes, little endian for integer fields:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | `R93SESS1` |
| 8 | 4 | Protocol version 1 |
| 12 | 16 | Build ID |
| 28 | 32 | Request nonce |
| 60 | 32 | SHA-256 of device ID |
| 92 | 32 | SHA-256 of license key |
| 124 | 8 | Issued epoch |
| 132 | 8 | Lease expiry epoch |
| 140 | 8 | License expiry epoch |
| 148 | 32 | SHA-256 of operational hexadecimal text |
| 180 | 32 | SHA-256 of engine bytes |

The lease lasts at most 180 seconds and never extends the license expiry.
P-256 ECDSA/SHA-256 signs the message; the existing DER signature response
format is retained. D1 atomically records nonce use across Worker isolates.
The replay table is created idempotently on first use and contains hashed
identities and lease expiry epochs, rather than license keys.

Health adds initialization protocol, build ID, program hash and decryption
readiness. It returns no program bytes. Production signing-key rotation
requires resealing the engine and updating the matching pinned client.

Validation runs the actual Worker with test-only keys and a test-recipient
envelope. Live Cloudflare execution and the matching compiled client still
require verification before merging this draft. Delivered client code can be
inspected after authorized delivery; this protocol does not make client code
impossible to reverse engineer.
