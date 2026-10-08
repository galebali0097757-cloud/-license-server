# r97 licensed menu actions

r97 clients now download a signed program containing the 19 menu action implementations, guest dialog construction, active-tab appearance, the existing UI layout, and the interpreted skin mapper. The client contains the bounded interpreter, authenticated dispatch stubs, UIKit adapters, and the existing game SDK.

The program is encrypted to the existing production P-256 key in this Worker. Its plaintext and owner sources are not public assets. Sessions bind the license, device, build, challenge, expiry, operation vector, and program digest. r97 uses its own replay table and preserves r88/r93/r94/r95/r96 routes.

Client dispatch checks the current program digest on every callback, authenticates the receiver and Objective-C class, verifies the installed method implementation, and stops after lease expiry or detected replacement. The registered controller is retained across lease renewals so existing UIKit targets remain valid.

This is interpreted data for an already signed iOS client. It does not download executable ARM64 modules, use JIT, or require another signing operation at login.

Program build: 452a7aced7d05bd971aba249489e8c3f
Program SHA-256: 96beb5d164b02f1882fbf1d13e4eca2ce1e3f2f293243b0c08e91671ca3cecc3
Program bytes: 127392
Entries: 26; UI instructions: 5016

Validation runs the actual Worker with disposable test keys and the compiled ARM64 client with mocked Apple/SDK interfaces. It covers license rejection, replay, expiry, program changes, method replacement, menu controls, all 50 skin selections, 60 color components, and lease renewal. Existing r95 and r96 Worker contracts were tested against this updated Worker. Physical iPhone/ESign and production customer-key login were not tested.

The signing secret, operational configuration, license database and prior encrypted programs are unchanged. Native SDK/render/hook installation helpers remain in the client. Client-side code and authenticated downloaded data are still inspectable on a device controlled by an attacker; this release does not promise impossible reverse engineering.
