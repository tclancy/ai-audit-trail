// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// testKey is one published test key: its kid, keyring role, and private key.
type testKey struct {
	kid  string
	role string
	priv ed25519.PrivateKey
}

// readSeeds parses spec/test-seed.txt into keys by kid. It does not accept a
// seed that is not exactly 32 bytes of hex, or a duplicate kid.
func readSeeds(path string) (map[string]testKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	keys := map[string]testKey{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		k, err := parseSeedLine(fields)
		if err != nil {
			return nil, err
		}
		if _, dup := keys[k.kid]; dup {
			return nil, fmt.Errorf("duplicate kid %q in %s", k.kid, path)
		}
		keys[k.kid] = k
	}
	return keys, sc.Err()
}

// parseSeedLine turns "<hex> <kid> <role> ..." into a testKey.
func parseSeedLine(fields []string) (testKey, error) {
	if len(fields) < 3 {
		return testKey{}, fmt.Errorf("seed line needs <hex> <kid> <role>: %q", fields)
	}
	seed, err := hex.DecodeString(fields[0])
	if err != nil || len(seed) != ed25519.SeedSize {
		return testKey{}, fmt.Errorf("seed for %s is not 32 bytes of hex", fields[1])
	}
	return testKey{kid: fields[1], role: fields[2], priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// window is a key's seq validity window; to < 0 means open-ended (null).
type window struct {
	kid      string
	from, to int64
}

// defaultWindows is the shared keyring: one gate key forever, one sink key.
func defaultWindows() []window {
	return []window{{kidGate1, 0, -1}, {kidSink, 0, -1}}
}

// rotationWindows is the keyring for vectors that rotate gate-test-1 to
// gate-test-2 at rotationSeq.
func rotationWindows() []window {
	return []window{{kidGate1, 0, rotationSeq}, {kidGate2, rotationSeq + 1, -1}, {kidSink, 0, -1}}
}

// keyring returns the canonical keyring bytes (SPEC §3.8) for the windows.
// It does not append a newline.
func (g *generator) keyring(ws []window) []byte {
	keys := make([]any, 0, len(ws))
	for _, w := range ws {
		k := g.keys[w.kid]
		var to any
		if w.to >= 0 {
			to = w.to
		}
		keys = append(keys, map[string]any{
			"alg":            "ed25519",
			"kid":            k.kid,
			"pub":            base64.StdEncoding.EncodeToString(k.priv.Public().(ed25519.PublicKey)),
			"role":           k.role,
			"valid_from_seq": w.from,
			"valid_to_seq":   to,
		})
	}
	return canonical(map[string]any{"keys": keys, "log_id": logID, "v": 1})
}
