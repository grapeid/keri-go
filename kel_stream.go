package keri

import (
	"fmt"
	"strings"
)

// A whole key log as one stream.
//
// An identity is published by serving its complete key log — did:webs resolves
// an identifier by fetching `keri.cesr` and replaying it. Until now this package
// could build and read one message at a time, which is enough to talk to a peer
// and not enough to publish.
//
// Writing the stream is concatenation. Reading it back is the real work: the
// messages are not delimited, so a reader has to know where each one ends. The
// event's own version string states its length, and every attachment group
// states how many primitives follow and at what width — so a stream is
// self-describing to a reader that knows the widths, and unreadable to one that
// guesses. That is why a group this package does not recognise is refused
// rather than skipped: skipping an unknown group means resuming at a position
// derived from a guess, and everything after it is then read as something it
// is not.

// ExportKEL writes signed messages as a single CESR stream.
//
// The messages must be a key log in order. This does not reorder them: a log's
// order is part of what it asserts, and a publisher that silently sorted would
// hide a caller's bug rather than surface it.
func ExportKEL(messages [][]byte) ([]byte, error) {
	if len(messages) == 0 {
		return nil, fmt.Errorf("there is no key log to export")
	}
	var out []byte
	var identifier string
	for i, m := range messages {
		event, attached, err := splitStream(m)
		if err != nil {
			return nil, fmt.Errorf("message %d is not an event with attachments: %w", i, err)
		}
		ev, err := ParseEvent(event)
		if err != nil {
			return nil, fmt.Errorf("message %d is not a readable event: %w", i, err)
		}
		if i == 0 {
			identifier = ev.Identifier
		} else if ev.Identifier != identifier {
			// A stream published at one identifier's URL must be that
			// identifier's log. Mixing two would let a reader attribute one
			// identity's events to another.
			return nil, fmt.Errorf("message %d belongs to %s but the log began with %s",
				i, ev.Identifier, identifier)
		}
		if len(attached) == 0 {
			return nil, fmt.Errorf("message %d carries no attachments, so nothing attests "+
				"that its controller produced it; refusing to publish it", i)
		}
		out = append(out, m...)
	}
	return out, nil
}

// ParseKELStream splits a stream back into the messages it holds.
//
// Every message is returned with its attachments, exactly as it appeared, so
// what comes out can be handed straight to ValidateSignedKEL. Re-serialising
// would risk changing a byte that a signature covers.
func ParseKELStream(stream []byte) ([][]byte, error) {
	if len(stream) == 0 {
		return nil, fmt.Errorf("there is no stream to read")
	}
	var out [][]byte
	rest := stream
	for len(rest) > 0 {
		// Leading whitespace between messages is tolerated: a stream may have
		// been through a tool that pretty-printed it.
		trimmed := strings.TrimLeft(string(rest), " \t\r\n")
		if trimmed == "" {
			break
		}
		rest = []byte(trimmed)

		event, after, err := splitStream(rest)
		if err != nil {
			return nil, fmt.Errorf("message %d: %w", len(out), err)
		}
		width, err := attachmentWidth(after)
		if err != nil {
			return nil, fmt.Errorf("message %d: %w", len(out), err)
		}
		out = append(out, rest[:len(event)+width])
		rest = after[width:]
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the stream holds no messages")
	}
	return out, nil
}

// attachmentWidth measures the attachment groups at the start of s, stopping at
// the next event.
//
// This is the function that makes a concatenated stream readable. It returns an
// error rather than a best guess for anything it does not understand: resuming
// at a guessed offset reads the remainder of the stream as something it is not,
// and the resulting events would be malformed in ways that look like corruption
// rather than like a parser bug.
func attachmentWidth(s []byte) (int, error) {
	used := 0
	for used < len(s) {
		// An event begins the next message; attachments are over.
		if s[used] == '{' {
			return used, nil
		}
		if s[used] != '-' && s[used] != '0' && s[used] != 'A' && s[used] != 'B' {
			// Not a counter and not an event. Rather than guess, say where.
			return 0, fmt.Errorf("at offset %d the stream is neither an attachment "+
				"counter nor the start of an event: %.8q", used, s[used:])
		}
		remaining := s[used:]
		if len(remaining) < 4 {
			return 0, fmt.Errorf("the stream ends after %d characters, which is not a "+
				"complete attachment counter", len(remaining))
		}
		code := string(remaining[:2])
		count, err := b64Int(string(remaining[2:4]))
		if err != nil {
			return 0, fmt.Errorf("the attachment counter %q is not readable: %w",
				remaining[:4], err)
		}
		body, err := groupBodyWidth(code, count, string(remaining[4:]))
		if err != nil {
			return 0, err
		}
		if len(remaining) < 4+body {
			return 0, fmt.Errorf("the attachment group %q declares %d characters and only "+
				"%d remain", code, body, len(remaining)-4)
		}
		used += 4 + body
	}
	return used, nil
}

// groupBodyWidth is how many characters follow a counter, by group.
//
// Stated as a table rather than derived, so that adding a group is a visible
// change somebody reviews. A width that is wrong here does not fail loudly — it
// silently reads the next message from the wrong offset.
//
// Indexed signatures, alone or inside a transferable receipt quadruple, are
// measured one by one, because each one's width depends on its own code (88
// characters for A and B, 92 for 2A and 2B).
func groupBodyWidth(code string, count int, body string) (int, error) {
	switch code {
	case counterControllerIdxSigs, counterWitnessIdxSigs:
		_, used, err := readIndexedSigs(code, body, count)
		return used, err
	case counterNonTransReceiptCouples:
		return count * (sizePrefix + sizeCigar), nil
	case CounterSealSourceCouples:
		return count * (sizeSeqner + saidPlaceholderLen), nil
	case counterTransReceiptQuadruples:
		return transReceiptQuadruplesWidth(code, body, count)
	case counterAttachedMaterial:
		// The count is in quadlets of four characters, and the body is another
		// sequence of groups — already measured by the count.
		return count * 4, nil
	default:
		return 0, fmt.Errorf("the attachment group %q is one this package cannot measure, "+
			"so where the next message begins is unknown", code)
	}
}
