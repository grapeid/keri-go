//go:build !kerigo_pqtest

package keri

import (
	"crypto/rand"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// A production build reads no post-quantum code: the table of codes beyond
// Ed25519 is empty (K9), a key under one is refused in an establishment event
// (K4), and a commitment to one is a digest like any other, opaque until it
// is opened.
func TestAProductionBuildReadsNoPostQuantumCode(t *testing.T) {
	if len(extraKeyCodes) != 0 || len(extraIndexedSigCodes) != 0 {
		t.Fatal("a production build registers codes beyond Ed25519's")
	}
	s, _ := GenerateSigner(true)
	n, _ := GenerateSigner(true)
	edKey, _ := s.PublicKey()
	edNext, _ := n.PublicKey()
	pqRaw := make([]byte, 1952)
	_, _ = rand.Read(pqRaw)
	pqKey, err := MatterQB64Sized("2AAE", pqRaw)
	if err != nil || len(pqKey) != 2608 {
		t.Fatalf("an ML-DSA-65 key is 2608 characters under its draft code: %d %v", len(pqKey), err)
	}
	d1, _ := NextDigest(edNext)
	d2, _ := Blake3SAID([]byte(pqKey))

	// A founding committing to the post-quantum key is accepted.
	icp, err := BuildInception(InceptionInput{Keys: []string{edKey}, NextDigests: []string{d1, d2},
		Isith: json.RawMessage(`"1"`), Nsith: json.RawMessage(`"1"`), Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateSignedKEL([][]byte{signed(t, icp, s)}); err != nil {
		t.Fatalf("a founding committing to a post-quantum key was refused: %v", err)
	}

	// One naming it as a key is refused.
	both, err := BuildInception(InceptionInput{Keys: []string{edKey, pqKey}, NextDigests: []string{d1},
		Isith: json.RawMessage(`"1"`), Nsith: json.RawMessage(`"1"`), Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateSignedKEL([][]byte{signed(t, both, s)}); err == nil ||
		!strings.Contains(err.Error(), "no code this build reads") {
		t.Fatalf("a founding naming a post-quantum key was not refused for it: %v", err)
	}
}

// An unknown signature code, and a known one a character short, are refused.
func TestAnUnknownOrShortSignatureIsRefused(t *testing.T) {
	s, _ := GenerateSigner(true)
	n, _ := GenerateSigner(true)
	edKey, _ := s.PublicKey()
	edNext, _ := n.PublicKey()
	d1, _ := NextDigest(edNext)
	icp, _ := BuildInception(InceptionInput{Keys: []string{edKey}, NextDigests: []string{d1},
		Isith: json.RawMessage(`"1"`), Nsith: json.RawMessage(`"1"`), Derivation: "self-addressing"})
	raw, _ := s.Sign(icp)
	big, _ := EncodeIndexedSignature(raw, SignaturePlace{Index: 0, Ondex: 1})
	for name, sig := range map[string]string{
		"an unknown code":          "3Z" + big[2:],
		"a 2A signature too short": big[:len(big)-1],
	} {
		// Framed by hand: AttachControllerSigs would refuse it before the
		// verifier saw it.
		frame, err := counterFrame(CounterControllerIdxSigs, 1)
		if err != nil {
			t.Fatal(err)
		}
		msg := append(append([]byte(nil), icp...), []byte(frame+sig)...)
		if _, err := ValidateSignedKEL([][]byte{msg}); err == nil {
			t.Fatalf("%s was accepted by the verifier", name)
		}
	}
}

// A founding listing an ECDSA key keripy reads, beside the Ed25519 key that
// signs it at a threshold of one, is accepted as keripy accepts it; the ECDSA
// key's own signature is never counted here (extra_codes.go).
func TestAKeyKeripyReadsIsReadThoughItsSignatureIsNotCounted(t *testing.T) {
	s, _ := GenerateSigner(true)
	n, _ := GenerateSigner(true)
	edKey, _ := s.PublicKey()
	edNext, _ := n.PublicKey()
	d1, _ := NextDigest(edNext)
	point := make([]byte, 33)
	point[0] = 2
	_, _ = rand.Read(point[1:])
	secp, err := MatterQB64Sized("1AAJ", point)
	if err != nil {
		t.Fatal(err)
	}
	icp, err := BuildInception(InceptionInput{Keys: []string{edKey, secp}, NextDigests: []string{d1},
		Isith: json.RawMessage(`"1"`), Nsith: json.RawMessage(`"1"`), Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateSignedKEL([][]byte{signed(t, icp, s)}); err != nil {
		t.Fatalf("a founding keripy accepts was refused: %v", err)
	}
	if PostQuantumTestCodes() {
		t.Fatal("a production build reads post-quantum test codes")
	}
}

// The file registering the post-quantum codes is not in a build without the
// tag, so no production binary can contain it.
func TestThePostQuantumTableIsNotInAProductionBuild(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{.GoFiles}}", ".").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	if strings.Contains(string(out), "pq_test_codes.go") {
		t.Fatalf("a build without the tag compiles the post-quantum codes: %s", out)
	}
}

// signed is raw with s's signature attached at place 0.
func signed(t *testing.T, raw []byte, s Signer) []byte {
	t.Helper()
	sig, err := s.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	q, err := EncodeIndexedSignature(sig, SamePlace(0))
	if err != nil {
		t.Fatal(err)
	}
	group, err := AttachControllerSigs([]string{q})
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte(nil), raw...), group...)
}
