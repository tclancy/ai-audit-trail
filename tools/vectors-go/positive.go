// SPDX-License-Identifier: Apache-2.0

package main

import "fmt"

// allVectors returns every vector of SPEC §11 in a fixed order.
func (g *generator) allVectors() []vector {
	return append(g.positiveVectors(), g.negativeVectors()...)
}

// positiveVectors returns the vectors a verifier must accept with exit 0.
func (g *generator) positiveVectors() []vector {
	return []vector{
		g.genesisBoot(),
		g.decisionVector("decision-approve", true),
		g.decisionVector("decision-reject", false),
		g.heartbeatVector(),
		g.anchorVector(),
		g.rotationVector(),
		g.rotationTwoFilesVector(),
	}
}

// genesisBoot is a log holding only its genesis boot record.
func (g *generator) genesisBoot() vector {
	c := g.newChain()
	c.boot()
	return positive("genesis-boot", c)
}

// decisionVector is genesis followed by one approve or reject decision.
func (g *generator) decisionVector(name string, approve bool) vector {
	c := g.newChain()
	c.boot()
	c.decision(approve)
	return positive(name, c)
}

// heartbeatVector is genesis, one decision, then a heartbeat with since_hb 1.
func (g *generator) heartbeatVector() vector {
	c := g.newChain()
	c.boot()
	c.decision(true)
	c.heartbeat()
	return positive("heartbeat", c)
}

// anchorVector is genesis, one decision, its anchor submission and signed
// sink receipt, and the anchor record that follows.
func (g *generator) anchorVector() vector {
	c := g.newChain()
	c.boot()
	c.decision(true)
	headSeq, head := c.seq-1, c.prev
	submission := signedLine(map[string]any{
		"head": head, "kid": kidGate1, "log_id": logID, "seq": headSeq,
		"ts": "2026-10-10T00:00:01.250Z", "v": 1,
	}, g.keys[kidGate1].priv, domainAnchor)
	receipt := signedLine(map[string]any{
		"entry": fmt.Sprintf("%s/%016d.json", logID, headSeq), "head": head, "log_id": logID,
		"proof": "", "seq": headSeq, "sink": kidSink, "sink_ts": "2026-10-10T00:00:01.500Z", "v": 1,
	}, g.keys[kidSink].priv, domainAnchorReceipt)
	c.anchor(head, receipt)
	v := positive("anchor", c)
	v.files["submission.json"] = concat(submission, "\n")
	v.files[fmt.Sprintf("anchors/%s/%016d.json", logID, headSeq)] = concat(receipt, "\n")
	return v
}

// rotationChain is genesis, a decision, rotation to gate-test-2 at
// rotationSeq, and a decision signed by gate-test-2.
func (g *generator) rotationChain() *chain {
	c := g.newChain()
	c.boot()
	c.decision(true)
	c.rotate(kidGate2)
	c.decision(true)
	return c
}

// rotationVector is rotationChain in one file with its own keyring.
func (g *generator) rotationVector() vector {
	v := positive("rotation", g.rotationChain())
	v.files["keyring.json"] = concat(g.keyring(rotationWindows()), "\n")
	return v
}

// rotationTwoFilesVector is rotationChain split into two files after the
// rotation record, so seq continuity and key windows cross a file boundary.
func (g *generator) rotationTwoFilesVector() vector {
	c := g.rotationChain()
	split := rotationSeq + 1
	return vector{kind: "positive", name: "rotation-two-files", lines: c.lines,
		files: map[string][]byte{
			logFileName(0):            jsonl(c.lines[:split]),
			logFileName(int64(split)): jsonl(c.lines[split:]),
			"keyring.json":            concat(g.keyring(rotationWindows()), "\n"),
		}}
}
