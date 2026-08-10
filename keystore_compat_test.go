package keri

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A key file written before the kind field existed must still load.
//
// v0.1.2 is public and fetchable, so someone may have a store on disk. Adding a
// required field to a stored record is exactly how a released version stops
// reading its own data.
func TestAKeyFileWithoutAKindStillLoads(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileKeyStore(dir, testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.Generate("legacy", true)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := original.PublicKey()

	// Rewrite the file as the previous version would have: no kind.
	path := filepath.Join(dir, base64Name("legacy"))
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatal(err)
	}
	delete(rec, "kind")
	out, _ := json.Marshal(rec)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileKeyStore(dir, testMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Signer("legacy")
	if err != nil {
		t.Fatalf("a key stored by an earlier version can no longer be read: %v", err)
	}
	pub, _ := got.PublicKey()
	if pub != want {
		t.Error("the recovered key is not the one that was stored")
	}
}
