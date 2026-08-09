package keri

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture is a real three-deep chain captured from keripy, not built here,
// so the test is not checking this package against itself.
func loadChain(t *testing.T) (map[string][]byte, map[string]string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("vectors", "credential_chain_fixture.json"))
	if err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	var raw map[string]string
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	creds := map[string][]byte{}
	for _, k := range []string{"root", "mid", "leaf", "wrong_schema"} {
		b, err := base64.StdEncoding.DecodeString(raw[k])
		if err != nil {
			t.Fatal(err)
		}
		creds[k] = b
	}
	return creds, raw
}

func resolverFor(t *testing.T, creds map[string][]byte, keys ...string) MapResolver {
	t.Helper()
	r := MapResolver{}
	for _, k := range keys {
		c, err := VerifyCredential(creds[k])
		if err != nil {
			t.Fatalf("fixture credential %q does not verify: %v", k, err)
		}
		r[c.SAID] = creds[k]
	}
	return r
}

// A chain verifies only when every credential it rests on does.
func TestAChainVerifiesToItsRoot(t *testing.T) {
	creds, meta := loadChain(t)
	chain, err := VerifyCredentialChain(creds["leaf"], resolverFor(t, creds, "root", "mid"))
	if err != nil {
		t.Fatalf("a complete chain was refused: %v", err)
	}
	if chain.Credential.SAID != meta["leaf_said"] {
		t.Errorf("verified %s, expected the leaf %s", chain.Credential.SAID, meta["leaf_said"])
	}
	if chain.Size() != 3 {
		t.Errorf("the chain holds %d credentials, expected 3", chain.Size())
	}
	if chain.Depth != 3 {
		t.Errorf("the chain is %d deep, expected 3", chain.Depth)
	}
	if len(chain.Depends) != 1 || chain.Depends[0].Credential.SAID != meta["mid_said"] {
		t.Fatal("the leaf does not depend on the middle credential")
	}
	if chain.Depends[0].Depends[0].Credential.SAID != meta["root_said"] {
		t.Error("the chain does not reach the root")
	}
}

// The case the whole type exists for. A leaf can be internally perfect and rest
// on something nobody can produce; treating that as verified is the mistake.
func TestAChainWithAMissingLinkIsRefused(t *testing.T) {
	creds, _ := loadChain(t)
	// The middle credential is present; the root it depends on is not.
	_, err := VerifyCredentialChain(creds["leaf"], resolverFor(t, creds, "mid"))
	if err == nil {
		t.Fatal("a chain was verified although a credential it depends on could not be " +
			"resolved; the leaf verifies on its own, which is exactly why this must not")
	}
	if !strings.Contains(err.Error(), "unverified") &&
		!strings.Contains(err.Error(), "could not be resolved") {
		t.Errorf("refused for an unclear reason: %v", err)
	}

	// And the leaf on its own still verifies, which is what makes the above
	// worth testing rather than obvious.
	if _, err := VerifyCredential(creds["leaf"]); err != nil {
		t.Errorf("the leaf does not verify on its own, so the test above proves nothing: %v", err)
	}
}

// An edge may pin the schema its target must have. Without that check, a chain
// is satisfied by a validly issued credential of entirely the wrong kind.
func TestAnEdgeRequiringTheWrongSchemaIsRefused(t *testing.T) {
	creds, _ := loadChain(t)
	_, err := VerifyCredentialChain(creds["wrong_schema"], resolverFor(t, creds, "root"))
	if err == nil {
		t.Fatal("a chain was verified although its edge required a schema the credential " +
			"it points at does not have")
	}
	if !strings.Contains(err.Error(), "schema") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// The resolver is not trusted to return what it was asked for.
func TestAResolverReturningTheWrongCredentialIsCaught(t *testing.T) {
	creds, meta := loadChain(t)
	honest := resolverFor(t, creds, "root", "mid")
	// A resolver that answers every question with the root.
	lying := MapResolver{}
	for said := range honest {
		lying[said] = creds["root"]
	}
	_, err := VerifyCredentialChain(creds["leaf"], lying)
	if err == nil {
		t.Fatal("a substituted credential was accepted; a compromised or merely buggy " +
			"resolver could satisfy any chain")
	}
	if !strings.Contains(err.Error(), meta["mid_said"]) &&
		!strings.Contains(err.Error(), "names") {
		t.Errorf("refused for an unclear reason: %v", err)
	}
}

// Verifying a chain without anywhere to resolve from is not verifying a chain.
func TestAChainNeedsAResolver(t *testing.T) {
	creds, _ := loadChain(t)
	if _, err := VerifyCredentialChain(creds["leaf"], nil); err == nil {
		t.Fatal("a chain was verified with no resolver, so nothing it depends on was checked")
	}
}

// A credential with no edges is a chain of one, and must still verify.
func TestAnUnchainedCredentialIsAChainOfOne(t *testing.T) {
	creds, meta := loadChain(t)
	chain, err := VerifyCredentialChain(creds["root"], MapResolver{})
	if err != nil {
		t.Fatalf("an unchained credential was refused: %v", err)
	}
	if chain.Size() != 1 || chain.Depth != 1 {
		t.Errorf("size %d depth %d, expected 1 and 1", chain.Size(), chain.Depth)
	}
	if chain.Credential.SAID != meta["root_said"] {
		t.Error("the wrong credential was verified")
	}
	if len(chain.Edges) != 0 {
		t.Errorf("found %d edges on a credential that has none", len(chain.Edges))
	}
}

// A chain that points at itself must terminate rather than loop.
func TestASelfReferentialChainTerminates(t *testing.T) {
	creds, meta := loadChain(t)
	// A resolver that answers the leaf's question with the leaf itself.
	loop := MapResolver{meta["mid_said"]: creds["leaf"]}
	_, err := VerifyCredentialChain(creds["leaf"], loop)
	if err == nil {
		t.Fatal("a chain resolving to itself was accepted")
	}
}

// Edges must be read in a stable order, or a chain verifies differently on
// different runs for reasons nobody can reproduce.
func TestEdgeOrderIsStable(t *testing.T) {
	creds, _ := loadChain(t)
	cred, err := VerifyCredential(creds["leaf"])
	if err != nil {
		t.Fatal(err)
	}
	var first []ChainEdge
	for i := 0; i < 20; i++ {
		edges, err := credentialEdges(cred)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = edges
			continue
		}
		if len(edges) != len(first) {
			t.Fatalf("run %d found %d edges, the first found %d", i, len(edges), len(first))
		}
		for j := range edges {
			if edges[j] != first[j] {
				t.Fatalf("run %d ordered edges differently: %+v against %+v",
					i, edges[j], first[j])
			}
		}
	}
}
