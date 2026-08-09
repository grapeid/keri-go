package keri

import (
	"encoding/json"
	"testing"
)

// The credential chain, pinned against keripy byte for byte.
//
// These bytes were produced by keripy 1.3.6 and compared against this package's
// output, not written down from what this package said. They cover the whole
// chain a verifier needs: the registry an issuance is recorded against, the
// credential document, the issuance that makes it live, and the revocation that
// ends it.
//
// This is a body check, not an acceptance check, and the distinction matters.
// A transaction event travels with a source seal couple naming the event in the
// issuer's key log that anchors it, and this package does not build that
// attachment yet — so keripy's Tevery cannot be handed one of these in a stream.
// Producing the right body is necessary and is established here; being
// transmissible is not, and is not claimed.
func TestTheCredentialChainMatchesKeripy(t *testing.T) {
	const (
		issuer    = "EA0zzubdGY84iWCachkiD1fOWISWIR7xUkBKUsIz2Up2"
		recipient = "EHtQ1cqprq_XvngppRKybLalrmvpImmoPRojhfSNpgna"
		schema    = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
		nonce     = "0ADYvfKAeqRVAyc-Gu0Zc7SN"
		issuedAt  = "2024-01-01T00:00:00.000000+00:00"
		revokedAt = "2024-06-01T00:00:00.000000+00:00"
	)

	registry, err := BuildRegistryInception(RegistryInput{Issuer: issuer, Nonce: nonce})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	const wantRegistry = "EIl6QsmXv4xyHWtFZl9q3sLVS-16_dAXptWGIZT6FUs4"
	regSAID := fieldOf(t, registry, "i")
	if regSAID != wantRegistry {
		t.Errorf("registry identifier is %s, keripy computes %s", regSAID, wantRegistry)
	}

	cred, err := BuildCredential(CredentialInput{
		SchemaSAID: schema, Issuer: issuer, Recipient: recipient, Registry: regSAID,
		Data: json.RawMessage(
			`{"dt":"2024-01-01T00:00:00.000000+00:00","LEI":"254900OPPU84GM83MG36"}`),
	})
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	credSAID := fieldOf(t, cred, "d")

	iss, err := BuildIssuance(IssuanceInput{
		CredentialSAID: credSAID, Registry: regSAID, DT: issuedAt,
	})
	if err != nil {
		t.Fatalf("issuance: %v", err)
	}
	const wantIssuance = "EDSmne3OH0ctfNAMIf4osG3Hyb0gO3KE_y51Fu41Qtnd"
	if got := fieldOf(t, iss, "d"); got != wantIssuance {
		t.Errorf("issuance identifier is %s, keripy computes %s", got, wantIssuance)
	}

	rev, err := BuildRevocation(RevocationInput{
		CredentialSAID: credSAID, Registry: regSAID,
		PriorISSSAID: fieldOf(t, iss, "d"), DT: revokedAt,
	})
	if err != nil {
		t.Fatalf("revocation: %v", err)
	}

	// A revocation must chain to the issuance it revokes. Without that link a
	// verifier cannot tell which issuance was ended, and a credential re-issued
	// later would appear revoked.
	if got := fieldOf(t, rev, "p"); got != wantIssuance {
		t.Errorf("the revocation chains to %s, but the issuance it revokes is %s",
			got, wantIssuance)
	}
	if got := fieldOf(t, rev, "i"); got != credSAID {
		t.Errorf("the revocation names %s, the credential is %s", got, credSAID)
	}

	// The credential must name the registry its status is recorded in, or a
	// verifier has nowhere to look to find out whether it was revoked.
	if got := fieldOf(t, cred, "ri"); got != regSAID {
		t.Errorf("the credential points at registry %s, the registry is %s", got, regSAID)
	}
	if got := fieldOf(t, cred, "s"); got != schema {
		t.Errorf("the credential names schema %s, expected %s", got, schema)
	}
}

func fieldOf(t *testing.T, raw []byte, name string) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not readable JSON: %v", err)
	}
	v, ok := m[name]
	if !ok {
		t.Fatalf("no %q field in %s", name, raw)
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		t.Fatalf("%q is not a string: %v", name, err)
	}
	return s
}
