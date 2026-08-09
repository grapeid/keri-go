package keri

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Verifying a credential that depends on another one.
//
// A chained credential carries an EDGE block naming, by digest, the credential
// it derives its authority from. A qualified issuer's credential points at the
// credential that qualified them; a guardian's authority points at the grant
// that created it. The chain is the point: the leaf claim is only worth what
// its root is worth.
//
// Verifying the leaf on its own establishes that its contents match its own
// identifier and nothing else. That is necessary and nowhere near sufficient —
// a credential can be internally perfect and chained to something revoked,
// forged, or absent. So an unresolvable chain is a FAILURE here, never a
// verified leaf with a warning attached: a caller who receives a verdict of
// "verified" must be able to rely on the whole chain having been checked.
//
// The edge block, as the reference writes it:
//
//	"e": {
//	  "d": "<digest of the edge block itself>",
//	  "<edge name>": {"n": "<credential this points to>", "s": "<its schema>"}
//	}

// maxChainDepth bounds how far a chain is followed.
//
// A bound rather than trust: a credential chain arrives from outside, and
// following one of unbounded length is a denial of service against the
// verifier. Deep chains are not a real shape — the vLEI hierarchy, the deepest
// in practice, is four.
const maxChainDepth = 16

// CredentialResolver finds a credential by its identifier.
//
// An interface because where credentials come from is not this package's
// business: a local store, a peer's agent, a registry service. What matters is
// that resolution can fail, and that failure is not the same as absence being
// acceptable.
type CredentialResolver interface {
	// Credential returns the credential with this identifier, or an error if it
	// cannot be found.
	Credential(said string) ([]byte, error)
}

// MapResolver resolves credentials from an in-memory map, for tests and for
// verifying a bundle that arrived all at once.
type MapResolver map[string][]byte

func (m MapResolver) Credential(said string) ([]byte, error) {
	raw, ok := m[said]
	if !ok {
		return nil, fmt.Errorf("no credential %s is held", said)
	}
	return raw, nil
}

// ChainEdge is one link: an edge name, and the credential it points to.
type ChainEdge struct {
	// Name is the edge's label, which says what the link MEANS — which
	// authority is being claimed, not merely that one exists.
	Name string
	// Target is the identifier of the credential depended on.
	Target string
	// Schema, when stated, is the schema that credential must have.
	Schema string
}

// VerifiedChain is a credential and everything it rests on.
type VerifiedChain struct {
	// Credential is the leaf that was asked about.
	Credential *Credential
	// Edges are the links out of the leaf.
	Edges []ChainEdge
	// Depends are the verified chains for each edge, in the same order.
	Depends []*VerifiedChain
	// Depth is how far this chain reaches, the leaf alone being one.
	Depth int
}

// Size is how many credentials the chain contains, including the leaf.
func (c *VerifiedChain) Size() int {
	n := 1
	for _, d := range c.Depends {
		n += d.Size()
	}
	return n
}

// edgeBlock is the `e` field: a digest of itself, then named links.
type edgeBlock map[string]json.RawMessage

type edgeTarget struct {
	N string `json:"n"`
	S string `json:"s"`
	O string `json:"o"`
}

// Edges reads the links out of a credential.
//
// The order is by edge name, so a chain verifies the same way twice. A map's
// iteration order in Go is deliberately random, and a verifier whose result
// depends on it would fail intermittently for reasons nobody could reproduce.
func credentialEdges(c *Credential) ([]ChainEdge, error) {
	if len(c.Edges) == 0 {
		return nil, nil
	}
	var block edgeBlock
	if err := json.Unmarshal(c.Edges, &block); err != nil {
		return nil, fmt.Errorf("the edge block is not readable: %w", err)
	}
	names := make([]string, 0, len(block))
	for name := range block {
		if name == "d" {
			// The edge block's own digest, not a link.
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]ChainEdge, 0, len(names))
	for _, name := range names {
		var t edgeTarget
		if err := json.Unmarshal(block[name], &t); err != nil {
			return nil, fmt.Errorf("the %q edge is not readable: %w", name, err)
		}
		if t.N == "" {
			return nil, fmt.Errorf("the %q edge names no credential, so there is nothing "+
				"to follow", name)
		}
		out = append(out, ChainEdge{Name: name, Target: t.N, Schema: t.S})
	}
	return out, nil
}

// VerifyCredentialChain verifies a credential and every credential it depends
// on, following the edge blocks.
//
// It fails if any link cannot be resolved or does not verify. That is the whole
// point: a leaf whose chain could not be checked has not been verified, and
// returning it as verified with the failure recorded somewhere would invite
// exactly the mistake this exists to prevent.
func VerifyCredentialChain(raw []byte, resolver CredentialResolver) (*VerifiedChain, error) {
	if resolver == nil {
		return nil, fmt.Errorf("verifying a chain needs somewhere to resolve credentials " +
			"from; a leaf on its own is not a verified chain")
	}
	return verifyChain(raw, resolver, map[string]bool{}, 0)
}

func verifyChain(raw []byte, resolver CredentialResolver, seen map[string]bool,
	depth int) (*VerifiedChain, error) {

	if depth >= maxChainDepth {
		return nil, fmt.Errorf("the chain is deeper than %d credentials; refusing to "+
			"follow further", maxChainDepth)
	}
	cred, err := VerifyCredential(raw)
	if err != nil {
		return nil, err
	}
	if seen[cred.SAID] {
		// A credential reachable from itself. The digests make this impossible
		// to create honestly — a credential would have to contain a digest of
		// something containing its own digest — so seeing one means the bundle
		// was built to make a verifier loop.
		return nil, fmt.Errorf("credential %s appears twice in its own chain, which "+
			"cannot happen by accident", cred.SAID)
	}
	seen[cred.SAID] = true
	// Removed on the way out, so two edges may legitimately point at the same
	// credential without the second being mistaken for a cycle.
	defer delete(seen, cred.SAID)

	edges, err := credentialEdges(cred)
	if err != nil {
		return nil, fmt.Errorf("credential %s: %w", cred.SAID, err)
	}

	chain := &VerifiedChain{Credential: cred, Edges: edges, Depth: 1}
	for _, edge := range edges {
		parentRaw, err := resolver.Credential(edge.Target)
		if err != nil {
			return nil, fmt.Errorf("credential %s depends on %s through its %q edge, and "+
				"that credential could not be resolved, so this chain is unverified: %w",
				cred.SAID, edge.Target, edge.Name, err)
		}
		parent, err := verifyChain(parentRaw, resolver, seen, depth+1)
		if err != nil {
			return nil, fmt.Errorf("credential %s depends on %s through its %q edge: %w",
				cred.SAID, edge.Target, edge.Name, err)
		}
		// The resolver was asked for a particular digest; check it returned it.
		// Trusting the resolver here would let a compromised or merely buggy one
		// substitute a different credential for the one the edge names.
		if parent.Credential.SAID != edge.Target {
			return nil, fmt.Errorf("the %q edge of %s names %s but the credential "+
				"resolved is %s", edge.Name, cred.SAID, edge.Target, parent.Credential.SAID)
		}
		// An edge may pin the schema the credential it points at must have.
		// Checking it is what stops a chain being satisfied by a credential of
		// the wrong KIND that happens to be validly issued.
		if edge.Schema != "" && parent.Credential.SchemaSAID != edge.Schema {
			return nil, fmt.Errorf("the %q edge of %s requires a credential of schema %s "+
				"but %s is of schema %s", edge.Name, cred.SAID, edge.Schema,
				parent.Credential.SAID, parent.Credential.SchemaSAID)
		}
		chain.Depends = append(chain.Depends, parent)
		if parent.Depth+1 > chain.Depth {
			chain.Depth = parent.Depth + 1
		}
	}
	return chain, nil
}
