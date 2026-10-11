// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// vector is one directory under positive/ or negative/.
type vector struct {
	kind  string            // "positive" or "negative"
	name  string            // directory name
	files map[string][]byte // relative path -> exact bytes
	// lines holds every record line (without "\n") in log order; positive
	// vectors list their hashes in vector.hash.
	lines [][]byte
	check int // negative only: first SPEC §5 check that fails
}

// logFileName is the SPEC §3.6 name of the file whose first record is firstSeq.
func logFileName(firstSeq int64) string {
	return fmt.Sprintf("%s.%016d.jsonl", logID, firstSeq)
}

// jsonl joins lines, each followed by "\n".
func jsonl(lines [][]byte) []byte {
	var b bytes.Buffer
	for _, l := range lines {
		b.Write(l)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// positive returns a single-file positive vector for the chain's lines.
func positive(name string, c *chain) vector {
	return vector{kind: "positive", name: name, lines: c.lines,
		files: map[string][]byte{logFileName(0): jsonl(c.lines)}}
}

// negative returns a single-file negative vector holding raw file bytes.
func negative(name string, check int, raw []byte) vector {
	return vector{kind: "negative", name: name, check: check,
		files: map[string][]byte{logFileName(0): raw}}
}

// sidecar returns the vector.hash or vector.expect file name and contents.
func (v vector) sidecar() (string, []byte) {
	if v.kind == "negative" {
		return "vector.expect", []byte(fmt.Sprintf("check=%d exit=2\n", v.check))
	}
	hashes := make([]string, len(v.lines))
	for i, l := range v.lines {
		hashes[i] = hashOf(l) + "\n"
	}
	return "vector.hash", []byte(strings.Join(hashes, ""))
}

// write creates the vector's directory under out and writes its files and sidecar.
func (v vector) write(out string) error {
	dir := filepath.Join(out, v.kind, v.name)
	name, body := v.sidecar()
	files := map[string][]byte{name: body}
	for p, b := range v.files {
		files[p] = b
	}
	for p, b := range files {
		path := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}
