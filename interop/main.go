// Command interop emits signed key events built by this package, for another
// KERI implementation to judge.
//
// The conformance suite proves one direction: given keripy's inputs, this
// package reproduces keripy's bytes. That is not the same as interoperating.
// It says nothing about whether keripy ACCEPTS what this package produces —
// a stricter question, because acceptance runs the reference's own validator
// over our output rather than comparing two strings.
//
// This writes a stream to stdout. tools/verify_interop.py feeds it to keripy.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	keri "github.com/grapeid/keri-go"
)

// seedFor derives a deterministic key, the same way the vector generator does,
// so a failure is about the event and never about which key was used.
func seedFor(tag byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = tag
	}
	return ed25519.NewKeyFromSeed(seed)
}

// qb64Key renders a public key the way CESR writes a transferable one: the
// code, then the key padded into base64 the way CESR pads it.
func qb64Key(pub ed25519.PublicKey) string {
	padded := append([]byte{0}, pub...)
	return keri.CodeEd25519 + base64.RawURLEncoding.EncodeToString(padded)[1:]
}

func qb64Digest(of string) string {
	said, err := keri.Blake3SAID([]byte(of))
	if err != nil {
		panic(err)
	}
	return said
}

// signIndexed frames a signature as an indexed controller signature.
func signIndexed(priv ed25519.PrivateKey, event []byte, index int) string {
	sig := ed25519.Sign(priv, event)
	padded := append([]byte{0, 0}, sig...)
	body := base64.RawURLEncoding.EncodeToString(padded)[2:]
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	return "A" + string(alphabet[index]) + body
}

func attach(sigs []string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := "-A" + "A" + string(alphabet[len(sigs)])
	for _, s := range sigs {
		out += s
	}
	return out
}

type message struct {
	Label string `json:"label"`
	Why   string `json:"why"`
	Event string `json:"event_b64"`
	Msg   string `json:"message_b64"`
}

func main() {
	a, b, c := seedFor('a'), seedFor('b'), seedFor('c')
	pubA := a.Public().(ed25519.PublicKey)
	pubB := b.Public().(ed25519.PublicKey)
	pubC := c.Public().(ed25519.PublicKey)

	var out []message
	emit := func(label, why string, event []byte, priv ed25519.PrivateKey) {
		sig := signIndexed(priv, event, 0)
		msg := append(append([]byte{}, event...), []byte(attach([]string{sig}))...)
		out = append(out, message{
			Label: label,
			Why:   why,
			Event: base64.StdEncoding.EncodeToString(event),
			Msg:   base64.StdEncoding.EncodeToString(msg),
		})
	}

	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys:        []string{qb64Key(pubA)},
		NextDigests: []string{qb64Digest(qb64Key(pubB))},
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
	emit("ixn/no-seals", "an interaction anchoring nothing", ixn, a)

	ixnEv, err := keri.ParseEvent(ixn)
	must(err)

	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix:      icpEv.Identifier,
		Keys:        []string{qb64Key(pubB)},
		PriorSAID:   ixnEv.SAID,
		SN:          2,
		NextDigests: []string{qb64Digest(qb64Key(pubC))},
	})
	must(err)
	emit("rot/to-precommitted-key", "rotating to the key the inception committed to", rot, b)

	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		must(err)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
