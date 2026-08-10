package keri

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func secretStores(t *testing.T) map[string]SecretStore {
	t.Helper()
	f, err := NewFileKeyStore(t.TempDir(), testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	return map[string]SecretStore{"file": f, "memory": NewMemoryKeyStore()}
}

// A secret survives a restart, which is the whole reason it is stored at all.
func TestASecretSurvivesAReopen(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("a post-quantum seed, as far as this package is concerned")

	store, err := NewFileKeyStore(dir, testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutSecret("identity/mldsa/0", secret); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileKeyStore(dir, testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Secret("identity/mldsa/0")
	if err != nil {
		t.Fatalf("a stored secret could not be read back: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Error("the secret changed in storage")
	}
}

// A secret must not be readable as a signing key, or the reverse. Both are
// bytes of plausible length in the same directory, and confusing them hands a
// caller material it did not ask for.
func TestSecretsAndKeysAreNotInterchangeable(t *testing.T) {
	for name, store := range secretStores(t) {
		t.Run(name, func(t *testing.T) {
			ks := store.(KeyStore)

			// A 32-byte secret is exactly the length of an Ed25519 seed.
			if err := store.PutSecret("looks-like-a-seed", bytes.Repeat([]byte{3}, 32)); err != nil {
				t.Fatal(err)
			}
			if _, err := ks.Signer("looks-like-a-seed"); err == nil {
				t.Error("a secret was returned as a signing key; it is the right length " +
					"and decrypts, so nothing else would have caught it")
			}

			if _, err := ks.Generate("a-real-key", true); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Secret("a-real-key"); err == nil {
				t.Error("a signing key was handed back as opaque secret material")
			}
		})
	}
}

// The same refusal to overwrite that keys get.
func TestASecretIsNeverSilentlyReplaced(t *testing.T) {
	for name, store := range secretStores(t) {
		t.Run(name, func(t *testing.T) {
			if err := store.PutSecret("k", []byte("first")); err != nil {
				t.Fatal(err)
			}
			if err := store.PutSecret("k", []byte("second")); err == nil {
				t.Fatal("a stored secret was replaced; whatever committed to it is lost")
			}
			got, err := store.Secret("k")
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "first" {
				t.Error("the secret changed despite the second write failing")
			}
		})
	}
}

func TestSecretStoresRefuseNonsense(t *testing.T) {
	for name, store := range secretStores(t) {
		t.Run(name, func(t *testing.T) {
			if err := store.PutSecret("", []byte("x")); err == nil {
				t.Error("a secret with no name was stored")
			}
			if err := store.PutSecret("empty", nil); err == nil {
				t.Error("an empty secret was stored; it reads back as valid and is not")
			}
			if _, err := store.Secret("never-stored"); err == nil {
				t.Error("reading an absent secret succeeded")
			}
		})
	}
}

// Secrets get the same encryption at rest as keys.
func TestAStoredSecretIsNotOnDiskInTheClear(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileKeyStore(dir, testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("SECRET-MARKER-do-not-find-this-in-a-file")
	if err := store.PutSecret("s", secret); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, secret) {
			t.Fatalf("%s holds the secret in the clear", e.Name())
		}
		info, _ := os.Stat(filepath.Join(dir, e.Name()))
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s is mode %o, readable beyond its owner", e.Name(), perm)
		}
	}

	wrong, err := NewFileKeyStore(dir, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Secret("s"); err == nil {
		t.Error("a secret was recovered under the wrong master key")
	} else if !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("refused for an unclear reason: %v", err)
	}
}
