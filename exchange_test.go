package keri

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type exchangeVectorFile struct {
	Cases []struct {
		Name  string `json:"name"`
		Input struct {
			Tag       string `json:"sender_seed_tag"`
			Recipient string `json:"recipient"`
			Prior     string `json:"prior"`
			DT        string `json:"dt"`
			Route     string `json:"route"`
			Data      string `json:"data"`
		} `json:"input"`
		Sender string `json:"sender"`
		SAID   string `json:"said"`
		Raw    string `json:"raw"`
		Stream string `json:"stream"`
	} `json:"cases"`
	Refusals []struct {
		Name   string `json:"name"`
		Stream string `json:"stream"`
	} `json:"refusals"`
}

func exchangeVectors(t *testing.T) exchangeVectorFile {
	t.Helper()
	b, err := os.ReadFile("vectors/keri_exchange_vectors_keripy-1.3.6.json")
	if err != nil {
		t.Fatal(err)
	}
	var f exchangeVectorFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) < 4 || len(f.Refusals) < 5 {
		t.Fatal("the vector file is missing cases")
	}
	return f
}

func exchangeKey(tag string) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte(strings.Repeat(tag, 32)))
}

// What keripy builds, this builds, byte for byte, and signs the same way.
func TestAnExchangeMessageIsWhatKeripyBuilds(t *testing.T) {
	for _, c := range exchangeVectors(t).Cases {
		t.Run(c.Name, func(t *testing.T) {
			key := exchangeKey(c.Input.Tag)
			sender, _ := MatterQB64(CodeEd25519N, key.Public().(ed25519.PublicKey))
			if sender != c.Sender {
				t.Fatalf("the sender key is %s, keripy's is %s", sender, c.Sender)
			}
			raw, err := BuildExchange(ExchangeInput{Sender: sender, Recipient: c.Input.Recipient,
				Prior: c.Input.Prior, DT: c.Input.DT, Route: c.Input.Route,
				Data: json.RawMessage(c.Input.Data)})
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != c.Raw {
				t.Fatalf("not keripy's bytes:\n got %s\nwant %s", raw, c.Raw)
			}
			stream, err := SignExchange(raw, key)
			if err != nil {
				t.Fatal(err)
			}
			if string(stream) != c.Stream {
				t.Fatalf("not keripy's signed message:\n got %s\nwant %s", stream, c.Stream)
			}
			got, err := VerifyExchangeSigned([]byte(c.Stream))
			if err != nil {
				t.Fatalf("a message keripy takes is refused: %v", err)
			}
			if got.SAID != c.SAID || got.Sender != c.Sender || got.Route != c.Input.Route ||
				got.Prior != c.Input.Prior || got.Recipient != c.Input.Recipient {
				t.Fatalf("read wrong: %+v", got.Exchange)
			}
		})
	}
}

// Each copy keripy refuses is refused here.
func TestWhatKeripyRefusesIsRefused(t *testing.T) {
	for _, r := range exchangeVectors(t).Refusals {
		t.Run(r.Name, func(t *testing.T) {
			if _, err := VerifyExchangeSigned([]byte(r.Stream)); err == nil {
				t.Fatal("a message keripy refuses was taken")
			}
		})
	}
}

func buildSample(t *testing.T) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	key := exchangeKey("q")
	sender, _ := MatterQB64(CodeEd25519N, key.Public().(ed25519.PublicKey))
	raw, err := BuildExchange(ExchangeInput{Sender: sender, Recipient: "EBHuxd-8Q6mUp5q7sGdnKq3m-hz5G0rkPEUZ6Ihm-JvB",
		DT: "2026-11-14T12:00:00.000000+00:00", Route: "/r", Data: json.RawMessage(`{"a":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	return raw, key
}

func TestAnExchangeMessageSpelledAnotherWayIsRefused(t *testing.T) {
	raw, _ := buildSample(t)
	var generic map[string]any
	_ = json.Unmarshal(raw, &generic)
	spaced := bytes.Replace(raw, []byte(`"t":"exn"`), []byte(`"t": "exn"`), 1)
	for name, bad := range map[string][]byte{
		"white space":                 spaced,
		"trailing":                    append(append([]byte(nil), raw...), ' '),
		"a changed content character": bytes.Replace(raw, []byte(`"a":1`), []byte(`"a":2`), 1),
		"an unknown field":            bytes.Replace(raw, []byte(`"e":{}}`), []byte(`"e":{},"x":1}`), 1),
	} {
		if _, err := VerifyExchange(bad); err == nil {
			t.Errorf("%s was read", name)
		}
	}
}

func TestOnlyTheSenderSignsAnExchangeMessage(t *testing.T) {
	raw, _ := buildSample(t)
	if _, err := SignExchange(raw, exchangeKey("z")); err == nil {
		t.Fatal("a key that is not the sender's signed it")
	}
}

func TestAnExchangeMessageNamesItsRecipientOnceAndCannotNameAnother(t *testing.T) {
	if _, err := BuildExchange(ExchangeInput{Sender: "BK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd",
		Recipient: "EBHuxd-8Q6mUp5q7sGdnKq3m-hz5G0rkPEUZ6Ihm-JvB", DT: "d", Route: "/r",
		Data: json.RawMessage(`{"i":"Eother"}`)}); err == nil {
		t.Fatal("content named a recipient of its own")
	}
	raw, _ := buildSample(t)
	forged := bytes.Replace(raw, []byte(`"rp":"EBHuxd-8Q6mUp5q7sGdnKq3m-hz5G0rkPEUZ6Ihm-JvB"`), []byte(`"rp":"EBHuxd-8Q6mUp5q7sGdnKq3m-hz5G0rkPEUZ6Ihm-JvC"`), 1)
	if _, err := VerifyExchange(forged); err == nil {
		t.Fatal("an altered recipient was read")
	}
}

// Go's JSON encoder escapes U+2028 and U+2029 and keripy does not, so a message
// holding either could not be keripy's bytes: it is refused, not built apart.
func TestAnExchangeMessageHoldingALineSeparatorIsRefused(t *testing.T) {
	for _, r := range []string{" ", " "} {
		if _, err := BuildExchange(ExchangeInput{Sender: "BK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd", DT: "d", Route: "/r",
			Data: json.RawMessage(`{"a":"x` + r + `y"}`)}); err == nil {
			t.Errorf("built a message holding %q", r)
		}
	}
	raw, _ := buildSample(t)
	if _, err := VerifyExchange(bytes.Replace(raw, []byte(`"a":1`), []byte("\"a\":\" \""), 1)); err == nil {
		t.Error("read a message holding U+2028")
	}
}
