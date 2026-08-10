# What this package costs

Measured on one machine, same method for both languages, 2026-08-09. Re-measure
rather than cite these if the answer matters — they will drift.

## Size

Linked binary delta over a bare binary of the same language, stripped. The Go
figure references the *entire* surface — every builder, the validator, chain
verification, the watcher, the file keystore — so nothing is dropped by the
linker that a real caller would keep.

| | adds |
|---|---|
| `keri-go` | **1,346 KB** |
| `keriox` + `teliox` + `cesrox` | **3,169 KB** |

About 1.8 MB smaller. On mobile the saving is close to the full 1.8 MB, because
the Go runtime is already in the app — the Go core is compiled in — so this
package's marginal cost is its own code, while the Rust library is an additional
one stacked on top.

## Parsing speed

One signed 391-byte inception, split into event and attachments, no
cryptography.

| | |
|---|---|
| Go (`splitStream` + `ParseEvent` + `parseAttachments`) | 3,377 ns/op |
| Rust (`cesrox::parse` + `Message::try_from`) | 5,012 ns/op |

**Do not read this as a speed win, for two reasons.**

They are not the same operation: keriox builds a richer typed structure than the
Go path does, so part of the gap is doing more work rather than doing it slower.

And it barely matters. One Ed25519 verification is about 28,000 ns — six to eight
times the whole parse — and it is the same algorithm in both. A three-witness
event needs four verifications, so parsing is a few percent of ingest either way.
See `cost_test.go`, which measures that directly.

The reasons to prefer this package are size, one language in the build instead
of two, and not shipping an EUPL-licensed library inside an Apache-2.0 project.
Speed is not one of them.

## One package, not a trimmed mobile build

The Identity Agent witnesses and watches only on desktop, which raises the
question of a cut-down build for phones. The answer is no, on the numbers above:
1.35 MB is not worth a second codebase, and Go's linker already drops what a
build does not reference — an app that never constructs a `Watcher` does not
carry its code.

A second repository would reintroduce exactly the problem this package exists to
remove: two implementations of one protocol drifting quietly apart, which is
what the Python sidecar and the Rust mobile library did for months.

If a hard size ceiling ever appears, the mechanism is build tags inside this
package — `//go:build !mobile` on the witness and watcher files — never a fork.
Build tags keep one source of truth and one test suite.
