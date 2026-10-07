# r95 single menu and transferred controls

The matching client uses one primary menu. The obsolete ImGui menu renderer,
its helpers and its draw/load/save callers are removed from the native core.
The core distributed in the owner source is already sanitized; it contains
76,624 erased bytes of legacy menu code. Native ESP, fonts, skin enum mapping
and preference handling remain at their established SDK addresses.

The encrypted r95 server program supplies the primary interface, including
ESP Settings (four themes, custom RGBA colors, widths/radius/line position),
Bullet Track controls and all 50 numeric skin rows with individual switches.
The client applies FOV and distance to Bullet Track selection, draws its FOV,
and uses the original HitPart effect. Emote selection uses its own effective
native enum instead of the old UI's shared helmet field.

Protocol/build: `r95` / `6de243d8ba8fca1bb3e81d94c6a4ac27`.
Program: 54,760 bytes; SHA-256
`03e51a8ff761bedc3779ca5a8d7a9deaccfff7344f35ee28120ffe5461b45333`.
Client dylib: 99,578,192 bytes; SHA-256
`d4d53e4ca7cd5ee8af881bf55b8eeb115bbfdaa1e7f215edca7e2b6200963bec`.

The Worker change is additive: r94, r93 and r88 retain their existing leases
and envelopes. The r95 program is decrypted with the existing Worker secret
only after authentication; its digest is bound to the signed device/key/nonce
session. Its separate D1 nonce table enforces an atomic 4,096-entry cap. The
health field `single_menu_initialization` reports r95 readiness.

Validation uses ephemeral test keys and the actual Worker implementation,
compiled ARM64 receipt/VM/UI callbacks, native skin enum mapping and target
filters. UIKit and game SDK transport are mocked. Tests cover all 60 color
components, 50 skin selections and flags, persistence, four themes, original
Hide/winged-logo behavior, Bullet Track filters and effects, integrity,
concurrent engine retirement and earlier protocol compatibility. No production
license, production private key, or real iPhone/game session was used.

Private owner UI source and plain initialization programs must stay outside
this public repository and static assets. Layout is server supplied; the
bounded interpreter, widget primitives and game SDK remain device-side. A
modified login-success flag cannot supply a missing engine. This is not a
promise that a fully controlled licensed device cannot extract its memory.
