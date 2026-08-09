// Command interop emits signed key events built by this package, for another
// KERI implementation to judge.
//
// The conformance suite proves one direction: given keripy's inputs, this
// package reproduces keripy's bytes. That is not the same as interoperating —
// it says nothing about whether keripy ACCEPTS what this package produces, a
// stricter question because acceptance runs the reference's own validator over
// our output rather than comparing two strings.
//
// Everything here goes through the package's public API — key derivation,
// signing, and attachment framing included. An earlier version hand-rolled
// those three in this file, which meant the harness proved the encoding in this
// file was right rather than the encoding the library ships.
//
// Writes a stream to stdout. interop/verify_interop.py feeds it to keripy.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	keri "github.com/grapeid/keri-go"
)

// signerFor derives a deterministic key, so a failure is about the event and
// never about which key was used. A real identity uses keri.GenerateSigner.
func signerFor(tag byte) keri.Signer {
	seed := bytes.Repeat([]byte{tag}, 32)
	s, err := keri.NewSoftwareSigner(seed, true)
	must(err)
	return s
}

type message struct {
	Label string `json:"label"`
	Why   string `json:"why"`
	Event string `json:"event_b64"`
	Msg   string `json:"message_b64"`
}

func main() {
	a, b, c := signerFor('a'), signerFor('b'), signerFor('c')
	pubA, err := a.PublicKey()
	must(err)
	pubB, err := b.PublicKey()
	must(err)
	pubC, err := c.PublicKey()
	must(err)

	nextB, err := keri.NextDigest(pubB)
	must(err)
	nextC, err := keri.NextDigest(pubC)
	must(err)

	var out []message
	emit := func(label, why string, event []byte, signers ...keri.Signer) {
		signed, err := keri.SignEvent(event, signers...)
		must(err)
		out = append(out, message{
			Label: label,
			Why:   why,
			Event: base64.StdEncoding.EncodeToString(signed.Event),
			Msg:   base64.StdEncoding.EncodeToString(signed.Message),
		})
	}

	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys:        []string{pubA},
		NextDigests: []string{nextB},
	})
	must(err)
	emit("icp/single-key", "the simplest identity there is", icp, a)

	icpEv, err := keri.ParseEvent(icp)
	must(err)

	ixn, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix:    icpEv.Identifier,
		PriorSAID: icpEv.SAID,
		SN:        1,
		Data:      []json.RawMessage{},
	})
	must(err)
	emit("ixn/no-seals", "an interaction, signed by the key in force", ixn, a)

	ixnEv, err := keri.ParseEvent(ixn)
	must(err)

	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix:      icpEv.Identifier,
		Keys:        []string{pubB},
		PriorSAID:   ixnEv.SAID,
		SN:          2,
		NextDigests: []string{nextC},
	})
	must(err)
	emit("rot/to-precommitted-key",
		"rotating to the key the inception committed to by digest", rot, b)

	// A two-key identity, to exercise indexed signatures rather than only the
	// single-signature case where every index is zero.
	d, e := signerFor('d'), signerFor('e')
	pubD, err := d.PublicKey()
	must(err)
	pubE, err := e.PublicKey()
	must(err)
	nextPair := []string{mustDigest(pubD), mustDigest(pubE)}
	multi, err := keri.BuildInception(keri.InceptionInput{
		Keys:        []string{pubA, pubC},
		Isith:       json.RawMessage(`"2"`),
		NextDigests: nextPair,
		Nsith:       json.RawMessage(`"2"`),
	})
	must(err)
	emit("icp/two-of-two", "both keys must sign, so both indices must be right", multi, a, c)

	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		must(err)
	}
}

func mustDigest(pub string) string {
	d, err := keri.NextDigest(pub)
	must(err)
	return d
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
