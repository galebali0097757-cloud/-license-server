# r94 server menu initialization

r93 downloaded callback registration but still retained the client functions
that constructed the menu, installed its logo/gestures and built the style
dialog. r94 moves those complete sequences to the licensed server program.

The matching client replaces `build`, `setup` and `showModeChooser` with
interpreter entry calls. The private program contains page order, control
labels, dimensions, layout math, safe/silent-mode branches, five skin category
selectors, logo placement, gestures and callback binding. Generic native
widgets, device/SDK operations and feature callbacks remain on the device.
The client requires the downloaded program to create the menu; it has no local
program, whole-menu layout template or alternate initialization entry.

Two obsolete Mach-O segments (`__RP_TEXT`, `__RP_DATA`) and their 81,920 file
bytes/load commands are physically deleted. The builder reuses their range
for the new payload and adjusts every affected linkedit offset. This is a
file-layout deletion, rather than retained zero-filled executable sections.
The final file size is 99,578,192 bytes, 49,536 bytes less than the delivered
r93 client. Native SDK/rendering code accounts for most of the remaining size.

Program delivery uses protocol `r94` and the existing licensing endpoint.
The engine is encrypted to the existing production P-256 key and becomes
available only after license/device validation. Its digest is bound to the
212-byte ECDSA lease along with build, nonce, key, device and operations.
Replay challenges are inserted atomically into D1 and leases expire within
180 seconds. Existing r93 and r88 requests keep their previous behavior.
No production private key or customer license was accessed during validation.

The public repository contains only the encrypted envelope. Do not upload the
private program, private program builder, client source or owner source archive
to this public repository or static assets.

Program: 44,448 bytes; SHA-256
`24c5804b9ad098f10b8c4ddd5fc039a08f590f7dccb930e43e48d7e31a91b4cc`.
Client: SHA-256
`475586d16a07ed84b95563724bb3c7278c86aef60ca5f64c2750008c6d8d6e68`.

Validation uses actual compiled ARM64 parser/interpreter/control code and the
actual Worker with temporary test-only signing keys: 21 login checks, 12
session/engine checks, 12 layout/setup checks, 15 control checks and 15 Worker
checks. The unchanged r93 routes also pass their 15 checks. Integrity tests
reject 17 mutation patterns at current security entry addresses and four
block replacements; recomputing hashes cannot forge the signed manifest.
The absence/layout scan checks 14,485,872 ARM64 instructions and finds no
unmapped direct branch. Native AddressSanitizer checks cover 3,000 publications
with two writers/four readers and balanced allocation/free counts. Exact D1
replay SQL is also checked against concurrent SQLite connections.

Apple widgets/framework transport and the SDK action are mocked in emulator
tests. A physical iOS device and live production license login have not been
tested. Downloaded client-side programs can be inspected by someone who
controls an authorized device; this design does not guarantee resistance to
all extraction or binary modification.
