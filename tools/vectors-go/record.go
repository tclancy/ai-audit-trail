// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/gowebpki/jcs"
)

// Signature domains, SPEC §3.3, including the trailing NUL.
var (
	domainRecord        = []byte("ai-audit-trail/v1/record\x00")
	domainAnchor        = []byte("ai-audit-trail/v1/anchor\x00")
	domainAnchorReceipt = []byte("ai-audit-trail/v1/anchor-receipt\x00")
)

const zeroHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// canonical returns the RFC 8785 bytes of obj. It panics on failure because
// every input is a fixed value in this source; a failure is a bug here.
func canonical(obj map[string]any) []byte {
	raw, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		panic(err)
	}
	return out
}

// signedLine builds a canonical line per SPEC §3.2: sign DOMAIN||JCS(obj
// without sig), insert sig, serialize again. It does not append "\n" and
// does not modify obj.
func signedLine(obj map[string]any, priv ed25519.PrivateKey, domain []byte) []byte {
	body := map[string]any{}
	for k, v := range obj {
		if k != "sig" {
			body[k] = v
		}
	}
	msg := append(append([]byte{}, domain...), canonical(body)...)
	body["sig"] = "ed25519:" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	return canonical(body)
}

// hashOf returns "sha256:<hex>" of b. Callers pass a line without its "\n".
func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// hashText is hashOf for an ASCII string such as "new_kid=gate-test-2".
func hashText(s string) string {
	return hashOf([]byte(s))
}
