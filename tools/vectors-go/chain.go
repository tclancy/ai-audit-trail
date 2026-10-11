// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"fmt"
)

// Fixed synthetic values. Nothing here is generated at run time.
const (
	logID       = "test"
	kidGate1    = "gate-test-1"
	kidGate2    = "gate-test-2"
	kidSink     = "sink-test-1"
	bootULID    = "01JAB000000000000000000000"
	gateActor   = "spiffe://test.local/gate"
	appActor    = "spiffe://test.local/app/test-app"
	appID       = "test-app"
	modelID     = "test-model-1"
	rotationSeq = 2
	bootConfig  = "heartbeat_s=60;anchor_max_s=900;anchor_every=1000;truncated_bytes=0"
	// candidate is the canonical bytes of the Candidate every decision binds to.
	candidate = `{"account":"acct-0001","amount":100}`
)

// generator holds the published keys; it has no other state.
type generator struct {
	keys map[string]testKey
}

// chain appends records to one log, tracking seq, prev, and the active kid.
// It does not validate what it is given; negative vectors rely on that.
type chain struct {
	g       *generator
	kid     string
	seq     int64
	prev    string
	sinceHB int64
	lines   [][]byte
}

// newChain starts an empty log at genesis signed by gate-test-1.
func (g *generator) newChain() *chain {
	return &chain{g: g, kid: kidGate1, prev: zeroHash}
}

// next returns the full field set for the next record of type typ, with the
// type-specific values (SPEC §3.4) given in specific overriding the defaults.
func (c *chain) next(typ string, specific map[string]any) map[string]any {
	f := map[string]any{
		"v": 1, "log_id": logID, "type": typ, "seq": c.seq, "boot": bootULID,
		"ts":            fmt.Sprintf("2026-10-10T00:00:%02d.000Z", c.seq),
		"mono":          c.seq * 1_000_000_000,
		"request_id":    fmt.Sprintf("01JAR%021d", c.seq),
		"actor":         gateActor,
		"app":           "gate",
		"template_hash": hashText("test-template-v1"),
		"model_id":      modelID,
		"policy_hash":   hashText("test-policy-v1"),
		"input_ref":     zeroHash,
		"oracle":        "not_consulted",
		"oracle_ref":    zeroHash,
		"decision":      "reject",
		"reason_v":      1,
		"since_hb":      0,
		"canary":        "not_run",
		"kid":           c.kid,
		"prev":          c.prev,
	}
	for k, v := range specific {
		f[k] = v
	}
	return f
}

// commit signs f with priv under domain, appends it, and advances seq/prev.
func (c *chain) commit(f map[string]any, priv ed25519.PrivateKey, domain []byte) []byte {
	line := signedLine(f, priv, domain)
	c.lines = append(c.lines, line)
	c.prev = hashOf(line)
	c.seq++
	return line
}

// add builds the next record of typ and commits it with the active key.
func (c *chain) add(typ string, specific map[string]any) []byte {
	return c.commit(c.next(typ, specific), c.g.keys[c.kid].priv, domainRecord)
}

// boot appends a boot record (genesis when seq is 0).
func (c *chain) boot() []byte {
	return c.add("boot", map[string]any{
		"reason": "R_BOOT", "cart_hash": c.prev, "oracle_ref": hashText(bootConfig),
	})
}

// decisionFields returns the specific fields of an approve or reject decision.
func decisionFields(approve bool) map[string]any {
	f := map[string]any{
		"actor": appActor, "app": appID, "cart_hash": hashText(candidate),
		"input_ref": hashText("test-input-0001"), "oracle_ref": hashText("acct-0001:100"),
		"canary": "pass", "oracle": "match", "decision": "approve", "reason": "R_ORACLE_MATCH",
	}
	if !approve {
		f["oracle"], f["decision"], f["reason"] = "mismatch", "reject", "R_ORACLE_MISMATCH"
	}
	return f
}

// decision appends a decision record.
func (c *chain) decision(approve bool) []byte {
	c.sinceHB++
	return c.add("decision", decisionFields(approve))
}

// heartbeat appends a heartbeat carrying the decisions since the last one.
func (c *chain) heartbeat() []byte {
	line := c.add("heartbeat", map[string]any{
		"reason": "R_HEARTBEAT", "cart_hash": hashText("audittrail-heartbeat"), "since_hb": c.sinceHB,
	})
	c.sinceHB = 0
	return line
}

// anchor appends an anchor record for a submitted head and its sink receipt line.
func (c *chain) anchor(head string, receiptLine []byte) []byte {
	return c.add("anchor", map[string]any{
		"reason": "R_ANCHOR", "cart_hash": head, "oracle_ref": hashOf(receiptLine),
	})
}

// rotate appends a rotation record signed by the old key, then switches to newKid.
func (c *chain) rotate(newKid string) []byte {
	line := c.add("rotation", map[string]any{
		"reason": "R_KEY_ROTATION", "cart_hash": hashText("new_kid=" + newKid),
	})
	c.kid = newKid
	return line
}
