// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// vectorsReadme is written to <out>/README.md so the layout description is
// generated alongside the vectors it describes.
//
//go:embed vectors_readme.md
var vectorsReadme string

// writeManifest writes out + ".sha256" in `sha256sum` format, one line per
// file under out in lexical order, with paths relative to out's parent so
// `cd spec && sha256sum -c vectors.sha256` works. It hashes nothing outside out.
func writeManifest(out string) error {
	out = filepath.Clean(out)
	parent := filepath.Dir(out)
	var b strings.Builder
	err := filepath.WalkDir(out, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(parent, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		b.WriteString(hex.EncodeToString(sum[:]) + "  " + filepath.ToSlash(rel) + "\n")
		return nil
	})
	if err != nil {
		return err
	}
	return os.WriteFile(out+".sha256", []byte(b.String()), 0o644)
}
