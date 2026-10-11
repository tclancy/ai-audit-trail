// SPDX-License-Identifier: Apache-2.0

package main

import "bytes"

// SPEC §5 check numbers recorded in vector.expect.
const (
	checkRoundTrip = 1
	checkSchema    = 2
	checkPrev      = 4
	checkSig       = 5
	checkReason    = 9
)

// negativeVectors returns one vector per rule in SPEC §11's negative list.
// Each records the first check, in SPEC §5 order, that it fails.
func (g *generator) negativeVectors() []vector {
	return append(g.byteNegatives(), g.signedNegatives()...)
}

// genesisLine is the canonical genesis boot line every byte-level negative edits.
func (g *generator) genesisLine() []byte {
	c := g.newChain()
	return c.boot()
}

// edit returns line with the single occurrence of old replaced by new. It
// panics if old does not occur exactly once, so an edit can never silently
// do nothing.
func edit(line []byte, old, new string) []byte {
	if bytes.Count(line, []byte(old)) != 1 {
		panic("edit target not unique: " + old)
	}
	return bytes.Replace(line, []byte(old), []byte(new), 1)
}

// concat returns a new slice holding b then s. It never shares b's backing
// array, so vectors built from one line cannot overwrite each other.
func concat(b []byte, s string) []byte {
	out := make([]byte, 0, len(b)+len(s))
	return append(append(out, b...), s...)
}

// byteNegatives are the genesis line with one non-canonical byte change.
// None of them can come out of a JCS encoder; all fail check 1.
func (g *generator) byteNegatives() []vector {
	l := g.genesisLine()
	nl := func(b []byte) []byte { return concat(b, "\n") }
	return []vector{
		negative("duplicate-key", checkRoundTrip, nl(edit(l, `{"actor":`, `{"v":1,"actor":`))),
		negative("float-1.0", checkRoundTrip, nl(edit(l, `"v":1}`, `"v":1.0}`))),
		negative("exponent-1e3", checkRoundTrip, nl(edit(l, `"mono":0,`, `"mono":1e3,`))),
		negative("negative-zero", checkRoundTrip, nl(edit(l, `"mono":0,`, `"mono":-0,`))),
		negative("non-ascii", checkRoundTrip, nl(edit(l, `"model_id":"test-model-1"`, "\"model_id\":\"test-model-é\""))),
		negative("unpaired-surrogate", checkRoundTrip, nl(edit(l, `"model_id":"test-model-1"`, `"model_id":"test-model-\ud800"`))),
		negative("bom", checkRoundTrip, concat([]byte("\xef\xbb\xbf"), string(l)+"\n")),
		negative("crlf", checkRoundTrip, concat(l, "\r\n")),
		negative("trailing-space", checkRoundTrip, concat(l, " \n")),
		negative("unsorted-keys", checkRoundTrip, nl(edit(edit(l, `,"v":1}`, `}`), `{"actor":`, `{"v":1,"actor":`))),
	}
}

// signedNegatives are canonical, correctly signed lines (unless the signature
// is the point) that break exactly one later rule.
func (g *generator) signedNegatives() []vector {
	return []vector{
		g.genesisVariant("int-2-pow-53", checkSchema, func(f map[string]any) { f["mono"] = int64(1) << 53 }),
		g.genesisVariant("extra-field", checkSchema, func(f map[string]any) { f["note"] = "x" }),
		g.genesisVariant("missing-field", checkSchema, func(f map[string]any) { delete(f, "canary") }),
		g.unknownReason(),
		g.zeroPrevAtSeq3(),
		g.wrongDomain(),
		g.retiredKid(),
	}
}

// genesisVariant is a genesis boot record with one field change, re-signed so
// the signature is valid for the changed contents.
func (g *generator) genesisVariant(name string, check int, change func(map[string]any)) vector {
	c := g.newChain()
	f := c.next("boot", map[string]any{
		"reason": "R_BOOT", "cart_hash": zeroHash, "oracle_ref": hashText(bootConfig),
	})
	change(f)
	c.commit(f, g.keys[kidGate1].priv, domainRecord)
	return negative(name, check, jsonl(c.lines))
}

// unknownReason is genesis then a decision whose reason matches the regex but
// is absent from reasons.txt section v=1.
func (g *generator) unknownReason() vector {
	c := g.newChain()
	c.boot()
	f := c.next("decision", decisionFields(true))
	f["reason"] = "R_NOT_A_REASON"
	c.commit(f, g.keys[kidGate1].priv, domainRecord)
	return negative("unknown-reason", checkReason, jsonl(c.lines))
}

// zeroPrevAtSeq3 is a valid chain whose record at seq 3 has a zero-hash prev.
func (g *generator) zeroPrevAtSeq3() vector {
	c := g.newChain()
	c.boot()
	c.decision(true)
	c.decision(false)
	f := c.next("decision", decisionFields(true))
	f["prev"] = zeroHash
	c.commit(f, g.keys[kidGate1].priv, domainRecord)
	return negative("zero-prev-seq-3", checkPrev, jsonl(c.lines))
}

// wrongDomain is genesis then a decision signed under the anchor domain.
func (g *generator) wrongDomain() vector {
	c := g.newChain()
	c.boot()
	c.commit(c.next("decision", decisionFields(true)), g.keys[kidGate1].priv, domainAnchor)
	return negative("wrong-domain", checkSig, jsonl(c.lines))
}

// retiredKid is the rotation chain plus a record signed by gate-test-1 after
// its valid_to_seq.
func (g *generator) retiredKid() vector {
	c := g.rotationChain()
	f := c.next("decision", decisionFields(true))
	f["kid"] = kidGate1
	c.commit(f, g.keys[kidGate1].priv, domainRecord)
	v := negative("retired-kid", checkSig, jsonl(c.lines))
	v.files["keyring.json"] = concat(g.keyring(rotationWindows()), "\n")
	return v
}
