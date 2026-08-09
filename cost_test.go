package keri

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// What actually costs time when an agent ingests a key event.
//
// The claim under test is that a faster wire encoding would speed up an agent
// meaningfully. That is only true if decoding is where the time goes, so this
// measures the three things done per event against each other.
var evt = []byte(`{"v":"KERI10JSON0001b7_","t":"icp","d":"EHtQ1cqprq_XvngppRKybLalrmvpImmoPRojhfSNpgna","i":"DKrCPrkD8X1WG4-yrIvtOrteh6KM3xa7Oc_-hQaOS4Fd","s":"0","kt":"1","k":["DKrCPrkD8X1WG4-yrIvtOrteh6KM3xa7Oc_-hQaOS4Fd"],"nt":"1","n":["EDOC2vSfll-dEl5J6VpZFvoJdYGrqImZUb5dpenC4Xb7"],"bt":"3","b":["BCZ_aHuuxFy3CW3VfIAIAiNmmpVd-1keLj6T6pYD9da6","BL0R47LBuViY8KuXNgAPMjn2O1U95HhtFzrXUS89feT_","BKDtywULdbP7aLdch9RBSjENGeBDD9pqdI6d88ObtAZ_"],"c":[],"a":[]}`)

func BenchmarkDecodeTheEvent(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(evt, &m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDigestTheEvent(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Blake3SAID(evt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyOneSignature(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, evt)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ed25519.Verify(pub, evt, sig) {
			b.Fatal("signature did not verify")
		}
	}
}
