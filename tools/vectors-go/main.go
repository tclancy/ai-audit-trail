// SPDX-License-Identifier: Apache-2.0

// Command vectors-go writes the conformance vectors of SPEC §11.
//
// It is the reference for canonical bytes and is not the code under test.
// Every value it writes is fixed in this source; nothing is random or read
// from the clock, so two runs produce identical bytes.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	out := flag.String("out", "", "directory to create and fill with vectors (must not exist or be empty)")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: go run . --out <dir>")
		os.Exit(2)
	}
	seedPath := filepath.Join(filepath.Dir(filepath.Clean(*out)), "test-seed.txt")
	if err := generate(*out, seedPath); err != nil {
		fmt.Fprintln(os.Stderr, "vectors-go:", err)
		os.Exit(1)
	}
}

// generate reads the published seeds, writes every vector under out, and
// writes the manifest to out + ".sha256". It does not overwrite: a non-empty
// out directory is an error.
func generate(out, seedPath string) error {
	keys, err := readSeeds(seedPath)
	if err != nil {
		return err
	}
	if err := requireEmptyDir(out); err != nil {
		return err
	}
	g := &generator{keys: keys}
	for _, v := range g.allVectors() {
		if err := v.write(out); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(out, "keyring.json"), concat(g.keyring(defaultWindows()), "\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "README.md"), []byte(vectorsReadme), 0o644); err != nil {
		return err
	}
	return writeManifest(out)
}

// requireEmptyDir creates dir if missing and fails if it already holds files.
// It never deletes anything.
func requireEmptyDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("%s is not empty; remove it first", dir)
	}
	return nil
}
