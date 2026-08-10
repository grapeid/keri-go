package keri

import (
	"encoding/json"
	"strings"
	"testing"
)

const replyWhen = "2026-08-10T12:00:00.000000+00:00"

// A reply must be the message its own identifier commits to. It is not part of
// a key log, so nothing else vouches for it — an altered one would otherwise be
// indistinguishable from the original.
func TestAReplyVerifiesAgainstItsOwnIdentifier(t *testing.T) {
	raw, err := EndpointLocation("BEndpointProvider", "https", "https://agent.example", replyWhen)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyReply(raw)
	if err != nil {
		t.Fatalf("a reply this package built does not verify: %v", err)
	}
	if got.Route != RouteLocationScheme {
		t.Errorf("route is %q", got.Route)
	}
	var payload map[string]string
	if err := json.Unmarshal(got.Data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["url"] != "https://agent.example" || payload["eid"] != "BEndpointProvider" {
		t.Errorf("the payload does not say what was stated: %v", payload)
	}
}

func TestAnAlteredReplyIsRefused(t *testing.T) {
	raw, err := EndpointLocation("BEndpointProvider", "https", "https://agent.example", replyWhen)
	if err != nil {
		t.Fatal(err)
	}
	altered := []byte(strings.Replace(string(raw), "agent.example", "attacker.test", 1))
	if len(altered) != len(raw) {
		t.Skip("the substitution changed the length, so this would fail for the wrong reason")
	}
	if _, err := VerifyReply(altered); err == nil {
		t.Fatal("a reply whose address was changed still verified")
	}
}

// Withdrawing a location is a statement, not an omission. An identity that has
// moved must be able to say so, or a dead address stays published.
func TestAnEmptyURLWithdrawsTheLocation(t *testing.T) {
	raw, err := EndpointLocation("BEndpointProvider", "https", "", replyWhen)
	if err != nil {
		t.Fatalf("an identity could not withdraw its address: %v", err)
	}
	got, err := VerifyReply(raw)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]string
	_ = json.Unmarshal(got.Data, &payload)
	if _, present := payload["url"]; !present {
		t.Error("the withdrawal dropped the url field rather than emptying it, so a recipient " +
			"cannot tell a withdrawal from a malformed message")
	}
}

// Authorising and withdrawing a role are distinguished by the route, so a
// recipient reading only that already knows which it holds.
func TestAuthorisingAndWithdrawingARoleDifferByRoute(t *testing.T) {
	add, err := EndpointRole("EController", "BWitness", "witness", true, replyWhen)
	if err != nil {
		t.Fatal(err)
	}
	cut, err := EndpointRole("EController", "BWitness", "witness", false, replyWhen)
	if err != nil {
		t.Fatal(err)
	}
	a, err := VerifyReply(add)
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyReply(cut)
	if err != nil {
		t.Fatal(err)
	}
	if a.Route != RouteEndRoleAdd || c.Route != RouteEndRoleCut {
		t.Fatalf("routes are %q and %q", a.Route, c.Route)
	}
	if a.SAID == c.SAID {
		t.Fatal("authorising and withdrawing produced the same message")
	}
}

// A reply with no timestamp could never be superseded, so it is refused rather
// than defaulted — a default would silently make one statement outrank another.
func TestAReplyWithoutATimestampIsRefused(t *testing.T) {
	if _, err := EndpointLocation("BEndpointProvider", "https", "https://x.example", ""); err == nil {
		t.Fatal("a reply with no timestamp was built")
	}
}

// The declared size must match the bytes, like every other message here.
func TestAReplyDeclaresItsOwnSize(t *testing.T) {
	raw, err := EndpointRole("EController", "BWitness", "witness", true, replyWhen)
	if err != nil {
		t.Fatal(err)
	}
	// The version string sits inside the first field, after `{"v":"`.
	_, _, size, err := ParseVersionString(string(raw[6:23]))
	if err != nil {
		t.Fatal(err)
	}
	if size != len(raw) {
		t.Fatalf("the reply declares %d bytes and is %d", size, len(raw))
	}
}
