# r96 interpreted skin initialization

The r96 client receives the menu initialization program, the skin field schema,
and a portable skin-mapping program only after a valid license/device check.
The new program uses the existing Worker signing secret. It is encrypted with
ECDH/HKDF/AES-GCM in this repository; the plaintext program and source are owner
inputs outside GitHub and outside the public asset directory.

The signed 212-byte session message binds the r96 build, fresh nonce, device,
license, lease times, operations, and the complete downloaded program digest.
The r96 nonce table enforces atomic insertion, expiry cleanup, and 4,096 rows.
The older r95/r94/r93/r88 verification paths and envelopes are preserved.

The client interprets data using a bounded precompiled runtime. Downloaded
ARM64 machine code is never made executable; there is no JIT, mmap, mprotect,
dlopen, additional downloaded dylib, or post-login Apple signing operation.
The containing app/library still needs its ordinary valid ESign installation.

This release moves the original skin enum-to-item mapper and its tables.
It does not move the native hook bootstrap, game SDK, widget adapters,
persistence helpers, or the 19 native UI callbacks. Those remain client code.
The existing server-owned menu layout and callback registration are retained.
It is not a completed migration of every native function and it cannot promise
that authorized client memory cannot be extracted.

## Pairing

- Protocol: `r96`
- Build: `61edc869ab37ce3174171ad05ff99739`
- Program: 96,120 bytes
- Program SHA-256: `556fe6a7344f29a5a88481958731b3500686b21b41188937e8ba17cf390297f6`
- Portable skin instructions: 2,018; module size: 40,528 bytes
- Client erasure: 8,072 native function bytes and 8,192 table bytes; the old
  entry is a branch into the authenticated interpreter. Native addresses are
  preserved, so this erasure does not compact the large SDK image.

## Validation

The original ARM64 mapper and the portable C++ interpreter produce the same
memory writes in 10,500 vectors: 500 individual selections and 10,000 combined
random preference states. The delivered ARM64 client passes login, signed
Worker roundtrip, menu layout, 50 skin selections/flags, 60 color components,
save/restore, bullet-track regression, repeated emote updates, and missing/
modified-program checks. Signed integrity tests detect 26 code/table mutations.
Engine lifetime stress passes 3,000 publications with six native threads and
AddressSanitizer. Worker r96 and existing r95 checks pass with disposable keys.

Apple APIs and game SDK objects are simulated in these checks. An iPhone/ESign
game session and a production customer-license login have not been tested.
CI deployment status must be checked separately from these offline results.
