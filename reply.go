package keri

import (
	"encoding/json"
	"fmt"
)

// Reply messages — how an identity says something about itself that is not a
// key event.
//
// A key event log records what an identity DID: founded, rotated, anchored. It
// deliberately does not record where that identity can be reached today, or
// which service currently acts for it, because those change for reasons that
// have nothing to do with key state and would otherwise bloat a log that every
// verifier has to replay forever.
//
// A reply carries that kind of statement instead. It is signed by the
// controller and stands on its own, so it can be superseded by a later one
// without the log growing, and a recipient keeps the most recent it has seen.
//
// The two shapes here are the ones an agent needs to be findable at all:
// where an endpoint is reachable, and who is authorised to act in a role.

const ilkReply = "rpy"

// Routes an agent uses. A route is what tells a recipient how to read the
// payload, so it is part of the message rather than a hint about it.
const (
	// RouteLocationScheme states the URL at which an endpoint is reachable.
	RouteLocationScheme = "/loc/scheme"
	// RouteEndRoleAdd authorises an endpoint provider in a role, and
	// RouteEndRoleCut withdraws that authorisation.
	RouteEndRoleAdd = "/end/role/add"
	RouteEndRoleCut = "/end/role/cut"
)

// rpyWire is a reply in the field order the message carries.
type rpyWire struct {
	V  string          `json:"v"`
	T  string          `json:"t"`
	D  string          `json:"d"`
	DT string          `json:"dt"`
	R  string          `json:"r"`
	A  json.RawMessage `json:"a"`
}

// ReplyInput is a statement an identity is making about itself.
type ReplyInput struct {
	// Route says how to read the payload.
	Route string
	// DT is when the statement was made, and is what lets a recipient tell a
	// newer statement from an older one. A reply with no timestamp could never
	// be superseded, so it is required rather than defaulted.
	DT string
	// Data is the payload, already in the order the route expects.
	Data json.RawMessage
}

// BuildReply assembles a signed-in-place reply message.
func BuildReply(in ReplyInput) ([]byte, error) {
	if in.Route == "" {
		return nil, fmt.Errorf("a reply must carry a route, or a recipient cannot know how " +
			"to read it")
	}
	if in.DT == "" {
		return nil, fmt.Errorf("a reply must say when it was made; without that a recipient " +
			"cannot tell it from an older statement and it could never be superseded")
	}
	if len(in.Data) == 0 {
		return nil, fmt.Errorf("a reply with no payload states nothing")
	}
	if !json.Valid(in.Data) {
		return nil, fmt.Errorf("the reply payload is not valid JSON")
	}
	w := rpyWire{
		V:  placeholderVersionString(ProtocolKERI, V1),
		T:  ilkReply,
		D:  saidDummy(),
		DT: in.DT,
		R:  in.Route,
		A:  in.Data,
	}
	dummy, err := serializeVersioned(w, ProtocolKERI, V1)
	if err != nil {
		return nil, err
	}
	said, err := saidOf(dummy)
	if err != nil {
		return nil, err
	}
	w.D = said
	return serializeVersioned(w, ProtocolKERI, V1)
}

// EndpointLocation states where an endpoint provider is reachable.
//
// An empty url is meaningful rather than missing: it withdraws the location,
// which is how an identity says "not here any more" instead of leaving an
// address published that no longer answers.
func EndpointLocation(eid, scheme, url, dt string) ([]byte, error) {
	if eid == "" {
		return nil, fmt.Errorf("a location statement must name the endpoint it is about")
	}
	if scheme == "" {
		scheme = "https"
	}
	data, err := json.Marshal(locationPayload{EID: eid, Scheme: scheme, URL: url})
	if err != nil {
		return nil, err
	}
	return BuildReply(ReplyInput{Route: RouteLocationScheme, DT: dt, Data: data})
}

type locationPayload struct {
	EID    string `json:"eid"`
	Scheme string `json:"scheme"`
	URL    string `json:"url"`
}

// EndpointRole authorises, or withdraws, an endpoint provider in a role.
//
// allow chooses the route rather than a field in the payload, because that is
// how the message distinguishes the two: a recipient reading only the route
// already knows which it is holding.
func EndpointRole(cid, eid, role string, allow bool, dt string) ([]byte, error) {
	if cid == "" || eid == "" {
		return nil, fmt.Errorf("a role statement must name both the controller making it and " +
			"the endpoint it is about")
	}
	if role == "" {
		role = "controller"
	}
	data, err := json.Marshal(rolePayload{CID: cid, Role: role, EID: eid})
	if err != nil {
		return nil, err
	}
	route := RouteEndRoleCut
	if allow {
		route = RouteEndRoleAdd
	}
	return BuildReply(ReplyInput{Route: route, DT: dt, Data: data})
}

type rolePayload struct {
	CID  string `json:"cid"`
	Role string `json:"role"`
	EID  string `json:"eid"`
}

// Reply is what a recipient reads out of a reply message.
type Reply struct {
	SAID  string
	Route string
	DT    string
	Data  json.RawMessage
	Raw   []byte
}

// VerifyReply checks that a reply is the message its own identifier commits to,
// and returns what it says.
//
// The digest check is the whole of it: a reply is not part of a key log, so
// nothing else vouches for it, and an altered one would otherwise be
// indistinguishable from the original.
func VerifyReply(raw []byte) (*Reply, error) {
	var w rpyWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("this is not a readable reply: %w", err)
	}
	if w.T != ilkReply {
		return nil, fmt.Errorf("this is a %q message, not a reply", w.T)
	}
	if w.D == "" {
		return nil, fmt.Errorf("the reply carries no identifier")
	}

	dummied := w
	dummied.D = saidDummy()
	dummy, err := serializeVersioned(dummied, ProtocolKERI, V1)
	if err != nil {
		return nil, err
	}
	said, err := saidOf(dummy)
	if err != nil {
		return nil, err
	}
	if said != w.D {
		return nil, fmt.Errorf("the reply does not match its own identifier, so it has been "+
			"altered since it was made: it says %s and computes to %s", w.D, said)
	}
	return &Reply{SAID: w.D, Route: w.R, DT: w.DT, Data: w.A, Raw: raw}, nil
}
