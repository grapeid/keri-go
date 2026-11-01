// Command judge validates key logs keripy built, and reports whether keri-go
// reaches the verdict keripy reached on each.
//
//	python interop/keripy_builds.py | go run ./interop/judge
//
// interop/main.go asks keripy to accept what keri-go builds. This asks the
// reverse, so neither implementation is only checked against itself. Exit
// status is non-zero on any disagreement.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	keri "github.com/grapeid/keri-go"
)

type kase struct {
	Label    string   `json:"label"`
	Why      string   `json:"why"`
	Expect   string   `json:"expect"`
	Codes    []string `json:"codes"`
	Messages []string `json:"messages_b64"`
	Keripy   string   `json:"keripy"`
}

func main() {
	var cases []kase
	if err := json.NewDecoder(os.Stdin).Decode(&cases); err != nil {
		fmt.Fprintln(os.Stderr, "the cases are not readable:", err)
		os.Exit(2)
	}
	if len(cases) == 0 {
		fmt.Fprintln(os.Stderr, "no cases were given, so nothing was judged")
		os.Exit(2)
	}
	agree, disagree := 0, 0
	for _, c := range cases {
		log := make([][]byte, len(c.Messages))
		for i, m := range c.Messages {
			b, err := base64.StdEncoding.DecodeString(m)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: message %d is not base64: %v\n", c.Label, i, err)
				os.Exit(2)
			}
			log[i] = b
		}
		verdict := "accepted"
		if _, err := keri.ValidateSignedKEL(log); err != nil {
			verdict = "refused: " + err.Error()
		}
		keripyAccepted := c.Keripy == "accepted"
		kerigoAccepted := verdict == "accepted"
		codes := strings.Join(c.Codes, ",")
		if keripyAccepted == kerigoAccepted {
			agree++
			word := "accepted"
			if !kerigoAccepted {
				word = "refused "
			}
			fmt.Printf("  %s by both  %-26s [%s] %s\n", word, c.Label, codes, c.Why)
			continue
		}
		disagree++
		fmt.Printf("  DISAGREE         %-26s [%s] keripy %s; keri-go %s\n",
			c.Label, codes, c.Keripy, verdict)
	}
	fmt.Printf("\n%d agree, %d disagree, out of %d built by keripy\n", agree, disagree, len(cases))
	if disagree > 0 {
		os.Exit(1)
	}
}
