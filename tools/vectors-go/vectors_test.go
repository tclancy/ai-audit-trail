// SPDX-License-Identifier: Apache-2.0

package main

// These tests read only the files the generator wrote, through a separate
// minimal checker, so a generator bug that produces self-consistent but
// wrong bytes in memory still has to survive a round trip through disk.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
)

const seedFile = "../../spec/test-seed.txt"

// generated writes a fresh vector set into a temp dir and returns its path.
func generated(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "vectors")
	if err := generate(out, seedFile); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGenerateIsByteIdenticalAcrossRuns(t *testing.T) {
	a, b := generated(t), generated(t)
	ma, _ := os.ReadFile(a + ".sha256")
	mb, _ := os.ReadFile(b + ".sha256")
	if len(ma) == 0 || !bytes.Equal(ma, mb) {
		t.Fatal("two runs produced different manifests")
	}
}

func TestGenerateRefusesNonEmptyOut(t *testing.T) {
	out := generated(t)
	if err := generate(out, seedFile); err == nil {
		t.Fatal("second generate into an already-filled dir succeeded")
	}
}

func TestPositiveVectorsPassEveryCheck(t *testing.T) {
	out := generated(t)
	dirs := vectorDirs(t, out, "positive")
	if len(dirs) != 7 {
		t.Fatalf("want 7 positive vectors, got %d", len(dirs))
	}
	for _, dir := range dirs {
		lines := readLog(t, dir)
		if failed := firstFailingCheck(t, out, dir, lines); failed != 0 {
			t.Errorf("%s: fails check %d", filepath.Base(dir), failed)
		}
		var want strings.Builder
		for _, l := range lines {
			want.WriteString(hashOf(l) + "\n")
		}
		got, _ := os.ReadFile(filepath.Join(dir, "vector.hash"))
		if string(got) != want.String() {
			t.Errorf("%s: vector.hash does not match its lines", filepath.Base(dir))
		}
	}
}

func TestNegativeVectorsFailAtTheirExpectedCheck(t *testing.T) {
	out := generated(t)
	dirs := vectorDirs(t, out, "negative")
	if len(dirs) != 21 {
		t.Fatalf("want 21 negative vectors, got %d", len(dirs))
	}
	for _, dir := range dirs {
		raw, _ := os.ReadFile(filepath.Join(dir, "vector.expect"))
		var want int
		if _, err := fmt.Sscanf(string(raw), "check=%d exit=2\n", &want); err != nil {
			t.Fatalf("%s: bad vector.expect %q", dir, raw)
		}
		if got := firstFailingCheck(t, out, dir, readLog(t, dir)); got != want {
			t.Errorf("%s: first failing check is %d, vector.expect says %d", filepath.Base(dir), got, want)
		}
	}
}

func TestLineTooLongIsExactlyOneByteOverTheSpecMaximum(t *testing.T) {
	out := generated(t)
	line := bytes.TrimSuffix(mustRead(t, filepath.Join(out, "negative", "line-too-long", logFileName(0))), []byte("\n"))
	if len(line) != 1399 { // SPEC §3.2 states 1398; the literal here pins the constant, as the Python does
		t.Fatalf("line-too-long is %d bytes, want 1399", len(line))
	}
	if nestingDepth(line) != 1 {
		t.Fatalf("line-too-long nests %d deep, want 1", nestingDepth(line))
	}
}

func TestNestingDepthCountsContainersOutsideStrings(t *testing.T) {
	cases := []struct {
		line  string
		depth int
	}{
		{`{}`, 1},
		{`{"a":[1]}`, 2},
		{`{"a":[[[[1]]]]}`, 5},
		{`{"a":[[[[[1]]]]]}`, 6},
		{`{"a":"{{{{{{{{"}`, 1},
		{`{"a":"[\"[[[[[[["}`, 1},
		{`{"a":"\\","b":[[[[[[1]]]]]]}`, 7},
		{`{"a":"\u0022[[[["}`, 1},
		{``, 0},
	}
	for _, c := range cases {
		if got := nestingDepth([]byte(c.line)); got != c.depth {
			t.Errorf("%s: depth %d, want %d", c.line, got, c.depth)
		}
	}
}

func TestNoTwoNegativeVectorsShareLogBytes(t *testing.T) {
	out := generated(t)
	seen := map[string]string{}
	for _, dir := range vectorDirs(t, out, "negative") {
		key := string(bytes.Join(readLogFiles(t, dir), []byte{0}))
		if other, dup := seen[key]; dup {
			t.Errorf("%s and %s have identical log bytes", filepath.Base(other), filepath.Base(dir))
		}
		seen[key] = dir
	}
}

func TestAnchorFilesVerifyUnderTheirOwnDomainsOnly(t *testing.T) {
	out := generated(t)
	dir := filepath.Join(out, "positive", "anchor")
	keys := loadKeyring(t, filepath.Join(out, "keyring.json"))
	cases := []struct {
		file, kid string
		domain    []byte
	}{
		{"submission.json", kidGate1, domainAnchor},
		{"anchors/test/0000000000000001.json", kidSink, domainAnchorReceipt},
	}
	for _, c := range cases {
		line := bytes.TrimSuffix(mustRead(t, filepath.Join(dir, c.file)), []byte("\n"))
		obj := parse(t, line)
		if !sigValid(obj, keys[c.kid].pub, c.domain) {
			t.Errorf("%s does not verify under its domain", c.file)
		}
		if sigValid(obj, keys[c.kid].pub, domainRecord) {
			t.Errorf("%s verifies under the record domain", c.file)
		}
	}
	logLines := readLog(t, dir)
	receipt := bytes.TrimSuffix(mustRead(t, filepath.Join(dir, cases[1].file)), []byte("\n"))
	if parse(t, logLines[2])["oracle_ref"] != hashOf(receipt) {
		t.Error("anchor record oracle_ref is not the hash of the sink receipt")
	}
}

// firstFailingCheck returns the first of SPEC §5 checks 1, 2 (field set and
// integer range only), 3, 4, 5, 9 that the log fails, or 0 if none.
func firstFailingCheck(t *testing.T, out, dir string, lines [][]byte) int {
	t.Helper()
	objs := make([]map[string]any, len(lines))
	for i, l := range lines {
		if !roundTrips(l) {
			return 1
		}
		objs[i] = parse(t, l)
	}
	for _, o := range objs {
		if !fieldsValid(o) {
			return 2
		}
	}
	for i, o := range objs {
		if o["seq"] != json.Number(fmt.Sprint(i)) {
			return 3
		}
	}
	for i, o := range objs {
		want := zeroHash
		if i > 0 {
			want = hashOf(lines[i-1])
		}
		if o["prev"] != want {
			return 4
		}
	}
	keys := keyringFor(t, out, dir)
	for i, o := range objs {
		k, ok := keys[o["kid"].(string)]
		if !ok || int64(i) < k.from || (k.to >= 0 && int64(i) > k.to) || !sigValid(o, k.pub, domainRecord) {
			return 5
		}
	}
	reasons := reasonsV1(t)
	for _, o := range objs {
		if !reasons[o["reason"].(string)] {
			return 9
		}
	}
	return 0
}

// roundTrips is check 1: ASCII only, within the SPEC §3.1 depth and §3.2
// length bounds (counted over the bytes before parsing), and
// JCS(parse(line)) == line.
func roundTrips(line []byte) bool {
	for _, c := range line {
		if c > 0x7e || c < 0x20 {
			return false
		}
	}
	if len(line) > maxLineBytes || nestingDepth(line) > maxNestingDepth {
		return false
	}
	got, err := jcs.Transform(line)
	return err == nil && bytes.Equal(got, line)
}

// nestingDepth is SPEC §3.1's structural depth: `{` and `[` outside string
// literals open a level, the outer object counting as 1; bytes inside a
// string literal, including escaped quotes, never change it.
func nestingDepth(line []byte) int {
	depth, deepest := 0, 0
	inString, escaped := false, false
	for _, c := range line {
		switch {
		case inString && escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case inString && c == '"':
			inString = false
		case inString:
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			depth++
			if depth > deepest {
				deepest = depth
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return deepest
}

// recordFields is SPEC §3.1's field list.
var recordFields = strings.Fields(`v log_id type seq boot ts mono request_id actor app
	template_hash model_id policy_hash input_ref cart_hash oracle oracle_ref decision
	reason reason_v since_hb canary kid prev sig`)

// stringRules is SPEC §3.1's regex or enum for every string field, anchored.
var stringRules = func() map[string]*regexp.Regexp {
	sha := `sha256:[0-9a-f]{64}`
	ulid := `[0-9A-HJKMNP-TV-Z]{26}`
	id := `[a-z0-9-]{1,32}`
	src := map[string]string{
		"log_id": id, "type": `boot|decision|heartbeat|anchor|rotation`, "boot": ulid,
		"ts":         `[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z`,
		"request_id": ulid, "actor": `spiffe://[a-z0-9.-]{1,64}/[a-z0-9/_.-]{1,128}`, "app": id,
		"template_hash": sha, "model_id": `[A-Za-z0-9._:-]{1,64}`, "policy_hash": sha,
		"input_ref": sha, "cart_hash": sha, "oracle": `match|mismatch|unavailable|timeout|not_consulted`,
		"oracle_ref": sha, "decision": `approve|reject`, "reason": `R_[A-Z0-9_]{1,40}`,
		"canary": `pass|fail|not_run`, "kid": id, "prev": sha, "sig": `ed25519:[A-Za-z0-9+/]{86}==`,
	}
	rules := map[string]*regexp.Regexp{}
	for f, s := range src {
		rules[f] = regexp.MustCompile(`^(?:` + s + `)$`)
	}
	return rules
}()

// fieldsValid is the part of check 2 this test needs: exact field set, every
// string matching its §3.1 rule, every number an integer in [0, 2^53), and
// nothing else as a value. It does not check the §3.4 per-type values.
func fieldsValid(o map[string]any) bool {
	if len(o) != len(recordFields) {
		return false
	}
	for _, f := range recordFields {
		v, ok := o[f]
		if !ok {
			return false
		}
		switch n := v.(type) {
		case string:
			rule, isString := stringRules[f]
			if !isString || !rule.MatchString(n) {
				return false
			}
		case json.Number:
			if _, isString := stringRules[f]; isString {
				return false
			}
			i, err := n.Int64()
			if err != nil || i < 0 || i >= 1<<53 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// sigValid checks obj's sig over DOMAIN || JCS(obj without sig).
func sigValid(obj map[string]any, pub ed25519.PublicKey, domain []byte) bool {
	s, _ := obj["sig"].(string)
	sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "ed25519:"))
	if err != nil || !strings.HasPrefix(s, "ed25519:") {
		return false
	}
	body := map[string]any{}
	for k, v := range obj {
		if k != "sig" {
			body[k] = v
		}
	}
	raw, _ := json.Marshal(body)
	canon, err := jcs.Transform(raw)
	return err == nil && ed25519.Verify(pub, append(append([]byte{}, domain...), canon...), sig)
}

type ringKey struct {
	pub      ed25519.PublicKey
	from, to int64
}

// keyringFor loads the vector's own keyring if it has one, else the shared one.
func keyringFor(t *testing.T, out, dir string) map[string]ringKey {
	own := filepath.Join(dir, "keyring.json")
	if _, err := os.Stat(own); err == nil {
		return loadKeyring(t, own)
	}
	return loadKeyring(t, filepath.Join(out, "keyring.json"))
}

// loadKeyring parses a keyring file; null valid_to_seq becomes -1. A kid or a
// pub listed twice fails the test (SPEC §3.8).
func loadKeyring(t *testing.T, path string) map[string]ringKey {
	t.Helper()
	var ring struct {
		Keys []struct {
			Kid  string `json:"kid"`
			Pub  string `json:"pub"`
			From int64  `json:"valid_from_seq"`
			To   *int64 `json:"valid_to_seq"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(mustRead(t, path), &ring); err != nil {
		t.Fatal(err)
	}
	keys := map[string]ringKey{}
	pubs := map[string]bool{}
	for _, k := range ring.Keys {
		pub, err := base64.StdEncoding.DecodeString(k.Pub)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := keys[k.Kid]; dup {
			t.Fatalf("%s: kid %q listed twice", path, k.Kid)
		}
		if pubs[k.Pub] {
			t.Fatalf("%s: pub of %q listed under two kids", path, k.Kid)
		}
		pubs[k.Pub] = true
		to := int64(-1)
		if k.To != nil {
			to = *k.To
		}
		keys[k.Kid] = ringKey{pub: pub, from: k.From, to: to}
	}
	return keys
}

// reasonsV1 returns the codes in spec/reasons.txt section [v=1].
func reasonsV1(t *testing.T) map[string]bool {
	t.Helper()
	codes := map[string]bool{}
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(mustRead(t, "../../spec/reasons.txt")))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "["):
			section = line
		case section == "[v=1]":
			codes[line] = true
		}
	}
	return codes
}

// readLog returns every line of the vector's .jsonl files in name order,
// without "\n". A file not ending in "\n" fails the test.
func readLog(t *testing.T, dir string) [][]byte {
	t.Helper()
	var lines [][]byte
	for _, data := range readLogFiles(t, dir) {
		if !bytes.HasSuffix(data, []byte("\n")) {
			t.Fatalf("%s: a log file does not end in a newline", dir)
		}
		lines = append(lines, bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))...)
	}
	return lines
}

// readLogFiles returns the raw bytes of the vector's .jsonl files in name order.
func readLogFiles(t *testing.T, dir string) [][]byte {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	sort.Strings(files)
	out := make([][]byte, len(files))
	for i, f := range files {
		out[i] = mustRead(t, f)
	}
	return out
}

// parse decodes a line keeping numbers as json.Number.
func parse(t *testing.T, line []byte) map[string]any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(line))
	d.UseNumber()
	var obj map[string]any
	if err := d.Decode(&obj); err != nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	return obj
}

// vectorDirs lists the vector directories under out/kind.
func vectorDirs(t *testing.T, out, kind string) []string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join(out, kind, "*"))
	if err != nil {
		t.Fatal(err)
	}
	return dirs
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
