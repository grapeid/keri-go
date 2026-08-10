# Running this package on a phone

Verified 2026-08-09 on macOS with the Xcode toolchain and gomobile.

## What is established

**It builds for both platforms.** `GOOS=ios GOARCH=arm64` and
`GOOS=android GOARCH=arm64` both compile the whole package. iOS needs
`CGO_ENABLED=1`, which is how gomobile builds anyway; Android `arm` (32-bit)
additionally needs the NDK toolchain present.

**It binds.** `gomobile bind` produces a working `.xcframework` for iOS and a
2.4 MB `.aar` for Android, with the expected symbols exported —
`KerimobileIncept`, `KerimobileValidateLog`, `KerimobileVersion`.

**The arm64 code path is already tested.** This matters more than it sounds. The
blake3 dependency ships amd64 assembly and a pure-Go implementation, selected by
`//go:build !amd64` — so arm64 uses the pure-Go one. The test suite runs on
darwin/arm64, which selects the same implementation a phone does. The 71
conformance cases that agree byte-for-byte with keripy have therefore been
exercising the exact digest code a phone will run, not a different one that
happens to pass on a laptop.

## What is not established

Nothing has run **on a device**. Building and binding are not running: a device
differs in memory limits, filesystem sandboxing, and background execution, none
of which a cross-compile exercises. `FileKeyStore` in particular writes to a
directory the caller supplies, and on iOS that must be a path inside the app
container — a detail that cannot fail on a laptop and will on a phone.

## The binding is a facade, deliberately

gomobile carries a restricted set of types across the language boundary:
strings, byte slices, ints, errors, and pointers to structs. Not slices of
strings, not maps, not interfaces over rich types. So this package cannot be
bound directly.

It should not be reshaped to suit that. keri-go is meant to be usable by
anybody, and bending its API around one consumer's toolchain would make it worse
for every other consumer. The binding therefore lives in a small facade package
that imports keri-go and flattens to JSON — which is what the Flutter side wants
anyway.

Adding `golang.org/x/mobile` to this module would pull a mobile-binding
dependency into a general-purpose library. The facade owns that dependency
instead.

## What blocks the integration

`grapeid/keri-go` is **private**. `identity-bot`, which holds `mobilecore` and
is where the binding would live, is **public**.

A public Go module cannot depend on a private one — anyone cloning identity-bot
would fail to build it, which for an open reference implementation is not a
rough edge but a broken promise. So the integration cannot proceed until that is
resolved one way or another, and the resolution is a decision about the open
source boundary rather than an engineering one.

Note also that today `mobilecore` starts the core with `EnableKeriDriver: false`
— KERI on mobile is handled by the Rust library, which is exactly what this
package exists to replace.
