package keri

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testMasterKey() []byte { return bytes.Repeat([]byte{7}, 32) }

func newTestStore(t *testing.T) (*FileKeyStore, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := NewFileKeyStore(dir, testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

// The point of the whole type: an identity survives the process that made it.
func TestAnIdentitySurvivesARestart(t *testing.T) {
	dir := t.TempDir()

	store, err := NewFileKeyStore(dir, testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	chain, err := NewKeychain(store, "identity", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := chain.Rotate(); err != nil {
		t.Fatal(err)
	}
	wantKeys, _ := chain.CurrentKeys()
	wantNext, _ := chain.NextDigests()
	generation := chain.Generation()

	// A new process: nothing in memory, only what is on disk.
	reopened, err := NewFileKeyStore(dir, testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadKeychain(reopened, "identity", 1, generation)
	if err != nil {
		t.Fatalf("an identity could not be reloaded from disk: %v", err)
	}
	gotKeys, _ := reloaded.CurrentKeys()
	gotNext, _ := reloaded.NextDigests()
	if gotKeys[0] != wantKeys[0] {
		t.Errorf("reloaded with %s in force, expected %s", gotKeys[0], wantKeys[0])
	}
	if gotNext[0] != wantNext[0] {
		t.Errorf("reloaded committed to %s, expected %s", gotNext[0], wantNext[0])
	}

	// And it can still rotate, which is what the committed successor is for.
	revealed, _, err := reloaded.Rotate()
	if err != nil {
		t.Fatalf("a reloaded identity could not rotate: %v", err)
	}
	d, err := NextDigest(revealed[0])
	if err != nil {
		t.Fatal(err)
	}
	if d != wantNext[0] {
		t.Error("the reloaded identity rotated to a key it had not committed to")
	}
}

// Signing must work across the restart, not just key recovery.
func TestAReloadedKeyProducesTheSameSignatures(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileKeyStore(dir, testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.Generate("k", true)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := original.PublicKey()
	msg := []byte("a message to sign")
	want, err := original.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileKeyStore(dir, testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.Signer("k")
	if err != nil {
		t.Fatal(err)
	}
	gotPub, _ := recovered.PublicKey()
	if gotPub != pub {
		t.Errorf("the reloaded key is %s, the original was %s", gotPub, pub)
	}
	got, err := recovered.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("the reloaded key produced a different signature over the same bytes")
	}
}

// The stored key must be unreadable to someone without the master key.
func TestKeysAreNotReadableFromDisk(t *testing.T) {
	store, dir := newTestStore(t)
	signer, err := store.Generate("secret", true)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := signer.PublicKey()
	// The seed, recovered through the store, is what must not appear on disk.
	sig, _ := signer.Sign([]byte("x"))

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one key file, found %d", len(entries))
	}
	body, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	// The public key is not secret, but the signature and any raw key material
	// must not be sitting in the file in the clear.
	if bytes.Contains(body, sig) {
		t.Error("signature material is on disk in the clear")
	}
	var record storedKey
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatalf("the key file is not the expected format: %v", err)
	}
	if record.Sealed == "" || record.Nonce == "" {
		t.Error("the key file carries no ciphertext")
	}
	if strings.Contains(string(body), pub) {
		t.Error("the key file contains the public key in the clear, which links the " +
			"file to an identity without the master key")
	}
}

// The wrong master key must fail loudly, not return a wrong key.
func TestTheWrongMasterKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileKeyStore(dir, testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Generate("k", true); err != nil {
		t.Fatal(err)
	}
	wrong, err := NewFileKeyStore(dir, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Signer("k"); err == nil {
		t.Fatal("a key was recovered under the wrong master key")
	}
}

// The attack the name-authentication prevents: swapping two key files so an
// identity signs with a key other than the one it believes it holds.
func TestSwappingTwoKeyFilesIsDetected(t *testing.T) {
	store, dir := newTestStore(t)
	if _, err := store.Generate("identity/0/0", true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Generate("identity/1/0", true); err != nil {
		t.Fatal(err)
	}

	a := filepath.Join(dir, base64Name("identity/0/0"))
	b := filepath.Join(dir, base64Name("identity/1/0"))
	bodyA, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	bodyB, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	// Swap the contents: each file now holds the other key's ciphertext.
	if err := os.WriteFile(a, bodyB, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, bodyA, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileKeyStore(dir, testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Signer("identity/0/0"); err == nil {
		t.Fatal("a swapped key file was accepted; the identity would sign with the key " +
			"it had committed to rotate to, revealing it early")
	}
}

// Altering the ciphertext must not produce a usable key.
func TestATamperedKeyFileIsRefused(t *testing.T) {
	store, dir := newTestStore(t)
	if _, err := store.Generate("k", true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, base64Name("k"))
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record storedKey
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal(err)
	}
	// Flip a character in the ciphertext.
	b := []byte(record.Sealed)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	record.Sealed = string(b)
	altered, _ := json.Marshal(record)
	if err := os.WriteFile(path, altered, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, _ := NewFileKeyStore(dir, testMasterKey())
	if _, err := reopened.Signer("k"); err == nil {
		t.Fatal("an altered key file produced a usable key")
	}
}

// Refusing to overwrite is enforced by the filesystem, so it cannot be raced.
func TestAnExistingKeyIsNeverReplaced(t *testing.T) {
	store, _ := newTestStore(t)
	first, err := store.Generate("k", true)
	if err != nil {
		t.Fatal(err)
	}
	pubFirst, _ := first.PublicKey()

	if _, err := store.Generate("k", true); err == nil {
		t.Fatal("an existing key was replaced; whatever committed to it is now lost")
	}
	again, err := store.Signer("k")
	if err != nil {
		t.Fatal(err)
	}
	pubAgain, _ := again.PublicKey()
	if pubAgain != pubFirst {
		t.Error("the key changed despite the second Generate failing")
	}
}

func TestKeyFilesAreNotWorldReadable(t *testing.T) {
	store, dir := newTestStore(t)
	if _, err := store.Generate("k", true); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, base64Name("k")))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("key file mode is %o; it is readable beyond its owner", perm)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("key directory mode is %o; it is listable beyond its owner", perm)
	}
}

func TestNamesRoundTripThroughTheFilesystem(t *testing.T) {
	store, _ := newTestStore(t)
	names := []string{"identity/0/0", "identity/1/0", "other identity/0/0", "a.b/c"}
	for _, n := range names {
		if _, err := store.Generate(n, true); err != nil {
			t.Fatalf("%q: %v", n, err)
		}
	}
	got, err := store.Names()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(names) {
		t.Fatalf("stored %d keys, listed %d: %v", len(names), len(got), got)
	}
	for _, n := range names {
		if _, err := store.Signer(n); err != nil {
			t.Errorf("%q could not be read back: %v", n, err)
		}
	}
}

func TestAMasterKeyOfTheWrongSizeIsRefused(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := NewFileKeyStore(t.TempDir(), bytes.Repeat([]byte{1}, n)); err == nil {
			t.Errorf("a %d-byte master key was accepted", n)
		}
	}
}

func TestPassphraseDerivationIsSaltedAndChecked(t *testing.T) {
	salt1, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	salt2, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(salt1, salt2) {
		t.Fatal("two salts were identical")
	}
	k1, err := DeriveMasterKey("correct horse battery staple", salt1)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveMasterKey("correct horse battery staple", salt2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k2) {
		t.Error("the same passphrase produced the same key under different salts, so " +
			"two stores would share a master key")
	}
	if len(k1) != masterKeyLen {
		t.Errorf("derived a %d-byte key, expected %d", len(k1), masterKeyLen)
	}
	if _, err := DeriveMasterKey("", salt1); err == nil {
		t.Error("an empty passphrase was accepted")
	}
	if _, err := DeriveMasterKey("x", []byte("short")); err == nil {
		t.Error("a short salt was accepted")
	}
}

// Two agents on disk, exchanging and verifying — the same scenario as the
// in-memory case, to confirm persistence changed nothing about the protocol.
func TestTwoPersistedAgentsStillVerifyEachOther(t *testing.T) {
	build := func(dir, label string) *Keychain {
		store, err := NewFileKeyStore(dir, testMasterKey())
		if err != nil {
			t.Fatal(err)
		}
		k, err := NewKeychain(store, label, 1)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	aliceChain := build(t.TempDir(), "alice")
	alice := &agent{name: "alice", chain: aliceChain, known: map[string]*SignedKELResult{}}
	bobChain := build(t.TempDir(), "bob")
	bob := &agent{name: "bob", chain: bobChain, known: map[string]*SignedKELResult{}}

	alice.incept(t)
	alice.rotate(t)
	res, err := bob.receive(alice.log)
	if err != nil {
		t.Fatalf("bob rejected a log signed by keys held on disk: %v", err)
	}
	inForce, _ := aliceChain.CurrentKeys()
	if res.Keys[0] != inForce[0] {
		t.Errorf("bob believes alice's key is %s, alice holds %s", res.Keys[0], inForce[0])
	}
}

// base64Name mirrors the store's filename encoding, so a test can find a file
// without reaching into unexported behaviour by guessing.
func base64Name(name string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(name)) + ".key"
}
