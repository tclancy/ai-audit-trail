# ai-audit-trail — Specification v0.1 (revision 2, post-review)

Repository: github.com/tclancy/ai-audit-trail. Python import roots: `audittrail`, `audittrail_verify`, `audittrail_testkit`.

**Status:** draft, revised after two independent reviews (see §14). **License:** Apache-2.0. **Reference language:** Python 3.12. **The wire format is the contract; the Python is one implementation of it.** Where this document and the Python disagree, this document wins and the Python is a bug.

---

## 0. One paragraph

ai-audit-trail is a small toolkit for systems that let an LLM-driven component *request* consequential actions but never *authorize* them. It provides (1) a signed, append-only, independently verifiable **decision log** in which a signed, *included* log entry is the only form an approval can take, together with the consumer-side rules that make a receipt mean something; and (2) a **test kit** for running such systems under load with scheduled fault injection and checking the log against safety invariants afterward. A third component, the **reference monitor** ("ref"), is specified here as an interface only and deferred to v0.2. ai-audit-trail contains no LLM code and never needs a model to run its tests.

## 1. Scope

### 1.1 In scope for v0.1

- `audittrail-log` — library: record schema, canonical serialization, hash chain, signing, anchoring, rotation, query index.
- `audittrail-verify` — standalone verifier CLI plus a **reconciler** that diffs consumer-held receipts against the log. Depends on the wire format and a keyring file; imports nothing from `audittrail-log`.
- `audittrail-testkit` — mock model server with chaos control, oracle stub, Locust harness with scheduled fault windows, post-run history check, app conformance test.
- `deploy/` — compose demo with explicit networks, a Vault-based signer, and a MinIO-based anchor sink.
- Threat model, invariants, acceptance tests, and conformance vectors.

### 1.2 Out of scope for v0.1

- The ref (policy evaluation, oracle adapters, cart typing). Interface only (§8).
- Content Disarm and Reconstruction / document pipelines.
- LLM client code, prompt handling, model-side defenses.
- Cloud KMS adapters as a *required* component. AWS KMS does offer Ed25519 (`ECC_NIST_EDWARDS25519`, see §12.2), so a `KmsSigner` is permitted in v0.1 as an optional adapter with moto-free integration tests gated on credentials; the reference non-exporting signer that the compose demo and CI use is Vault Transit, because it needs no cloud account.
- Rekor / public transparency logs as a sink (stretch; the anchor format reserves room for an inclusion proof).
- Production-grade isolation. Compose demonstrates topology, not a security boundary (§9.4).
- Multi-writer logs. One log, one `log_id`, one writer identity.

### 1.3 Non-goals

- ai-audit-trail does not make a compromised gate harmless. It makes the gate's actions attributable, bounds how far back history can be rewritten, and makes unlogged approvals detectable by reconciliation.
- ai-audit-trail does not decide whether a request is a good idea.
- ai-audit-trail does not store content. Hashes and pointers only.
- "Approve in the log" does not mean "action taken." The consumer's own log is authoritative for what was done.

## 2. Vocabulary

| Term | Meaning |
|---|---|
| **Gate** | The one component permitted to write a given log and issue receipts for it. v0.1: a stub used by the test kit. v0.2: the ref. |
| **Record** | One log line. Types: `boot`, `decision`, `heartbeat`, `anchor`, `rotation`. |
| **Receipt** | The bytes of a `decision` record, returned to the caller. Proves *signing*. Inclusion is proved by reconciliation (§6). |
| **Consumer** | Anything that acts on a receipt. Consumers verify, bind, deduplicate, and keep their own action log. They never mint. |
| **Verifier** | A process holding public keys only. Runs in CI, at gate boot (chain + signatures only), on a laptop. |
| **Reconciler** | Part of the verifier package. Diffs consumer action logs against the gate log. |
| **Anchor** | The chain head copied to an append-only store the gate's identity can append to and nothing else. |
| **Keyring** | Pinned public keys by `kid` with validity windows in `seq`. Owned by the verifier side. |
| **Candidate** | A strictly parsed, typed request. Hashes are computed from Candidates, never from raw input. |

## 3. Wire format

### 3.1 Record

One JSON object per line. **Strict**: no unknown fields, no duplicate keys, no floats, no non-ASCII bytes anywhere, every string matched against its regex. All integers in `[0, 2^53)`. All fields required for every record type; type-specific values are listed in §3.4.

| Field | Type / regex | Meaning |
|---|---|---|
| `v` | int, `== 1` | schema version; binds algorithm set (§3.3) |
| `log_id` | `[a-z0-9-]{1,32}` | identifies this log; a record is only meaningful in its own log |
| `type` | `boot \| decision \| heartbeat \| anchor \| rotation` | |
| `seq` | int | starts at 0 at genesis; +1 per record, across rotations, forever |
| `boot` | ULID `[0-9A-HJKMNP-TV-Z]{26}` | identifies the gate process incarnation; changes only at a `boot` record |
| `ts` | `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z` | gate wall clock, UTC, ms |
| `mono` | int | gate monotonic clock, ns since this `boot`; non-decreasing within a `boot` |
| `request_id` | ULID | generated by the gate |
| `actor` | `spiffe://[a-z0-9.-]{1,64}/[a-z0-9/_.-]{1,128}` | attested caller identity; from the channel, never the body |
| `app` | `[a-z0-9-]{1,32}` | registered app id |
| `template_hash` | `sha256:[0-9a-f]{64}` | signed prompt template in force |
| `model_id` | `[A-Za-z0-9._:-]{1,64}` | exact provider model id |
| `policy_hash` | `sha256:[0-9a-f]{64}` | policy in force |
| `input_ref` | `sha256:[0-9a-f]{64}` | hash of raw quarantined input — **a name for forensics, not a claim about content** |
| `cart_hash` | `sha256:[0-9a-f]{64}` | hash of canonical Candidate bytes |
| `oracle` | `match \| mismatch \| unavailable \| timeout \| not_consulted` | |
| `oracle_ref` | `sha256:[0-9a-f]{64}` | hash of compared value; zero-hash if not consulted |
| `decision` | `approve \| reject` | |
| `reason` | `R_[A-Z0-9_]{1,40}` | must exist in the reasons file at `reason_v` |
| `reason_v` | int | reasons enum version |
| `since_hb` | int | decision records written since the previous heartbeat (0 on non-heartbeats) |
| `canary` | `pass \| fail \| not_run` | |
| `kid` | `[a-z0-9-]{1,32}` | signing key id |
| `prev` | `sha256:[0-9a-f]{64}` | hash of previous line's bytes; zero-hash only at `seq == 0` |
| `sig` | `ed25519:[A-Za-z0-9+/]{86}==` | standard base64 with padding, 64-byte signature |

Zero-hash is `sha256:` followed by 64 `0` characters.

A record line nests at most **5** levels, counting the outer object as level 1. This is a resource bound, not a canonicality rule: a line nested deeper than 5 is rejected before it is parsed and reported under check 1 as not a record line; a line nested 5 or fewer levels is parsed, and any value that is an object or an array then fails check 2. Nothing in this specification or any conforming implementation raises the bound.

### 3.2 Canonical line and hashing

The on-disk line **is** the canonical bytes. Construction:

1. Build the record without `sig`. Serialize with RFC 8785 (JCS). Call these bytes `body`.
2. `sig = Ed25519.sign(DOMAIN_RECORD || body)`.
3. Insert `sig` and serialize the complete record with JCS. Call these bytes `line`. Append `\n`.

The maximum length of a record line is derived from the field bounds in §3.1, not chosen by hand: the sum, over the 25 fields in key order, of the key's length plus 3 (quotes and colon) plus the value's maximum length (the longest string the field's regex or enum admits, plus 2 for its quotes; 16 digits for an integer field other than `v`, whose only value is `1`), plus 24 commas and 2 braces. For schema `v == 1` that is **1398 bytes**, without the trailing `\n`. A line longer than the maximum fails check 1 before it is parsed. Implementations compute the maximum from the same table they validate against and must obtain this number.

Verification requires `line == JCS(parse(line))` byte for byte. Any difference, including whitespace, key order, number formatting, or escaping, is a verification failure, not something to normalize. This reduces every implementation's parser to a round-trip check and removes parser semantics from the trust path.

`hash(record) = sha256(line)` — over the line bytes **without** the trailing `\n`, and **including** `sig`. Ed25519 is deterministic, so there is exactly one valid line per (record contents, key). The chain and the anchors therefore commit to *who signed*, not just what was said.

`prev` of record *n+1* is `hash(record n)`. NFC normalization is not used; non-ASCII is forbidden by the regexes, so there is nothing to normalize.

### 3.3 Signature and domains

Schema `v == 1` binds **Ed25519 only**. There is no algorithm field and no negotiation. A future algorithm is a schema version bump.

| Domain constant | Used for |
|---|---|
| `b"ai-audit-trail/v1/record\x00"` | records |
| `b"ai-audit-trail/v1/anchor\x00"` | anchor submissions |
| `b"ai-audit-trail/v1/anchor-receipt\x00"` | sink receipts (if the sink signs) |

A signature under one domain never verifies under another (invariant I11).

### 3.4 Record types

| `type` | `decision` | `oracle` | `reason` | `cart_hash` | `oracle_ref` | notes |
|---|---|---|---|---|---|---|
| `boot` | `reject` | `not_consulted` | `R_BOOT` or `R_BOOT_TRUNCATED` | hash of the last verified line at boot; the zero-hash at genesis (`seq == 0`), where no line precedes it | sha256 of ASCII `heartbeat_s=<n>;anchor_max_s=<n>;anchor_every=<n>;truncated_bytes=<n>` | **only** record at which `boot` may change and `mono` may reset to 0 |
| `decision` | as decided | as consulted | as decided | Candidate hash | compared value hash | the only type `Approved` accepts |
| `heartbeat` | `reject` | `not_consulted` | `R_HEARTBEAT` | sha256(`audittrail-heartbeat`) | zero-hash | emitted from the request-serving loop, not a side thread; `since_hb` carries the count. Heartbeats are chain records so the head moves on the clock, not on traffic: a quiet night still produces distinct heads for each anchor, each anchor becomes a sink-timestamped proof that nothing else was written in that interval, and the verifier can tell "quiet" from "dead" or "redirected" |
| `anchor` | `reject` | `not_consulted` | `R_ANCHOR` | the head hash submitted | sha256 of the sink's `AnchorReceipt` line | marks that a submission was made |
| `rotation` | `reject` | `not_consulted` | `R_KEY_ROTATION` | sha256 of ASCII `new_kid=<kid>` | zero-hash | signed by the **old** key; the next record is signed by the new key |

Every string field not listed above carries its normal value. On non-decision records (`boot`, `heartbeat`, `anchor`, `rotation`), `actor` is the gate's own identity and `app` is the literal `gate`.

### 3.5 Reasons file

`reasons.txt`, ASCII, sections headed `[v=N]`, one code per line. The verifier loads all sections; a record's `reason` must appear in its `reason_v` section; unknown version or code → failure.

### 3.6 Log files and rotation

JSON Lines, UTF-8 (ASCII in practice), `\n` terminated. Files are named `<log_id>.<first_seq:016d>.jsonl`. Rotation is performed **only** by `Log` (never by external logrotate): it writes a `rotation`-free boundary (no special record; `seq` simply continues), fsyncs the old file, creates the new file, fsyncs the directory. The verifier accepts an ordered list of files and requires `seq` continuity across them.

**Genesis** is `seq == 0` with zero-hash `prev`, exactly once per `log_id`. A zero-hash `prev` at any other `seq` is a failure. A verification set that does not begin at `seq == 0` is reported `prefix_unverified` and exits 4, never 0.

### 3.7 Anchor submission and receipt

Submission (JCS, signed under the anchor domain):

```
{"head":"sha256:…","kid":"…","log_id":"…","seq":4123,"sig":"ed25519:…","ts":"…","v":1}
```

Sink receipt (JCS; the sink may sign under the anchor-receipt domain with its own key, which the keyring lists separately):

```
{"entry":"<sink-specific id, [A-Za-z0-9/._-]{1,128}>","head":"sha256:…","log_id":"…","proof":"","seq":4123,"sink":"[a-z0-9-]{1,32}","sink_ts":"…","sig":"","v":1}
```

`proof` is reserved for an inclusion proof (Rekor, v0.2); empty string in v0.1. `sink_ts` is the only clock in the system the gate does not control, and the verifier uses it (§5, check 8).

Sink object key: `<log_id>/<seq:016d>.json`. The sink **must** be configured so the gate's identity can create an object at a new key and can neither overwrite, delete, nor shorten retention. The verifier lists **all versions**; a second version at any key is a fork.

### 3.8 Keyring file

JCS object, owned by the verifier side, never writable by the gate's identity:

```
{"keys":[{"alg":"ed25519","kid":"gate-2026q4","pub":"<base64 32 bytes>","role":"gate","valid_from_seq":0,"valid_to_seq":null}, {"alg":"ed25519","kid":"sink-minio-1","pub":"…","role":"sink",…}],"log_id":"ingest-prod","v":1}
```

A `kid` verifies only records whose `seq` lies in its window. A `rotation` record at `seq = k` signed by the old key sets the old key's `valid_to_seq = k` and the new key's `valid_from_seq = k+1`; the keyring must agree or verification fails. Consumers refuse receipts whose `kid` is retired (see §6).

## 4. Library API (`audittrail-log`)

```python
class Signer(Protocol):
    kid: str
    def sign(self, domain: bytes, data: bytes) -> bytes: ...
    # Nothing returns key material.

class SoftwareSigner(Signer):     # refuses to construct unless AUDITTRAIL_DEV=1
class VaultTransitSigner(Signer)  # HashiCorp Vault transit, ed25519, sign-only policy; key never exported (reference)
class KmsSigner(Signer)           # optional; AWS KMS ECC_NIST_EDWARDS25519, ED25519_SHA_512, MessageType RAW only

class AnchorSink(Protocol):
    def append(self, submission: bytes) -> AnchorReceipt: ...   # append only

class FileAnchorSink(AnchorSink)    # dev; separate directory, separate OS user recommended
class S3ObjectLockSink(AnchorSink)  # works against MinIO (compose) and AWS S3; PutObject-only credentials

class Log:
    def __init__(self, dir, log_id, signer, anchor, keyring_path,
                 heartbeat_s=60, anchor_every=1000, anchor_max_s=900): ...
    def record(self, fields: DecisionFields) -> Receipt   # the only write path for decisions
    def heartbeat(self) -> Receipt
    def anchor(self) -> Receipt
    def rotate_key(self, new_signer: Signer) -> Receipt

class DecisionFields:   # dataclass; every str is enum- or regex-validated at construction (I8)

class Receipt:          # @final; __slots__; unpicklable; bytes of one decision line
    line: bytes
    entry: Record
    def verify(self, keyring: Keyring) -> bool

class Approved:         # see §6 for the wire-level rules this enforces
    @classmethod
    def from_wire(cls, line: bytes, keyring: Keyring, *, candidate: Candidate,
                  app: str, log_id: str, max_age_s: int, seen: SeenStore) -> "Approved"

def build_index(files, sqlite_path) -> None
```

Behavioral rules (each pinned in §7):

- `Log.record` takes a file lock, reads the last complete line **from disk**, computes `prev`, writes the line, `fsync(fd)`, releases. If the in-memory head and disk head disagree → raise. On an empty current file while an earlier file for this `log_id` exists → raise (never re-genesis).
- `Log.record` raises `LogUnavailable` on any failure and never returns a partial result. It also raises if more than `anchor_max_s` has elapsed since the last successful anchor (§12.1).
- Boot: `Log.__init__` discards a trailing line that lacks `\n` **and** fails strict parse, then verifies the last `N` lines (chain + signatures + schema, via the published `audittrail-verify` package at a pinned version, never a vendored copy), then writes a `boot` record (`R_BOOT_TRUNCATED` with the byte count if anything was discarded). It does not read the sink; fork detection is the external verifier's job.
- `anchor_every` counts `decision` records only.
- Rotation per §3.6; `fsync(dir)` after creating a file.
- No function produces a `Receipt` from arbitrary bytes. Deserialization yields `Record`. Consumers use `Approved.from_wire`, which enforces §6.
- `Receipt`, `Approved`, `Record` raise in `__init_subclass__` and are unpicklable. These are process hygiene, not wire properties, and are listed as tests, not as invariants.

## 5. Verifier (`audittrail-verify`)

Input: ordered log files, keyring, reasons file, optional anchor directory (pulled from the sink by a separate tool so the verifier has no cloud dependencies), optional consumer action logs, and an optional `--now <RFC 3339 UTC>` that replaces the wall clock for the staleness check (7) and the anchor-cadence check (8). `--now` exists so a fixed-date conformance vector can be verified to exit 0; a production run never passes it, and a report records which clock was used. Output: JSON report; exit codes: `0` all checks ran and passed; `2` failure; `3` I/O or internal error (every exception is caught and mapped to 3); `4` passed but one or more checks were skipped or the prefix is unverified. **CI requires 0.**

Checks, all mandatory when their inputs are present:

1. Each line round-trips: `line == JCS(parse(line))`. Strict parse (no duplicate keys, no floats, ASCII only). Nesting depth greater than 5, or line length greater than the §3.2 maximum, fails this check before parsing; both are counted over the bytes, in front of the JSON parser, so that every implementation reports the same check regardless of its parser's own limits.
2. Schema and regexes (§3.1); type-specific values (§3.4).
3. `seq` starts at 0 in the first file and increases by exactly 1 across the file set.
4. `prev` equals `sha256` of the previous line; zero-hash only at `seq 0`.
5. `sig` verifies under the keyring key for `kid`, with that key's `seq` window and the record domain. `rotation` records update the expected window.
6. `boot` changes only at `boot` records; `mono` non-decreasing within a `boot`; `ts` non-decreasing across the file set.
7. Heartbeats: `heartbeat_s` is read from the most recent `boot` record (not from the command line). No two consecutive records may be more than `2 × heartbeat_s` apart in `ts` without a `heartbeat` between them. **Staleness:** if `now − last.ts > 2 × heartbeat_s`, report `stale`, where `now` is the wall clock unless `--now` was given.
8. Anchors (when the anchor directory is present): every `anchor` record's `oracle_ref` matches the sha256 of a sink receipt line; every sink receipt's `head` equals the hash of the record at its `seq`; sink receipts are checked for forks (two receipts for one `seq`, or heads that do not descend); **`record.ts` at an anchored seq ≤ `sink_ts` + 60 s** (fabricated timestamps bounded by the sink's clock); **anchor cadence:** no more than `anchor_every` decision records and no more than `anchor_max_s` of `ts` between anchors, and the head must be anchored within `anchor_max_s` of `last.ts` — otherwise `anchor_gap`.
9. Reasons: `reason` present in section `reason_v`.
10. Reconciliation (when consumer action logs are present): every acted-upon receipt's `(log_id, seq, hash)` must equal the line at that `seq` in the log. A mismatch is `unlogged_approval` and is the most severe finding the verifier produces.

The verifier package has no imports from `audittrail-log`. Its import root is `audittrail_verify`. It is tested against committed fixtures in `spec/`, never against logs produced by `audittrail-log` in the same test run.

## 6. Consumer rules (wire-level; what a receipt means)

A receipt proves that the gate's key signed a `decision` record. For a consumer to act on it, **all** of the following must hold, in any language:

1. `line == JCS(parse(line))`, schema valid, `type == "decision"`, `decision == "approve"`.
2. `sig` verifies under the keyring key for `kid`, that key's `role == "gate"`, its window includes `seq`, and the key is not retired (a retired key is accepted only within `grace_s`, default 300, of its `valid_to_seq` record's `ts`).
3. `log_id` equals the consumer's configured `log_id`. Staging receipts do not verify in production because the keyrings differ *and* the `log_id` differs.
4. `app` equals the app the consumer is acting for.
5. `cart_hash == sha256(candidate.canonical_bytes())` for the Candidate the consumer is about to act on. **A receipt not bound to a cart authorizes nothing.**
6. `now − ts ≤ max_age_s`.
7. `request_id` has not been acted on before (`SeenStore`, durable).
8. The consumer appends `{log_id, seq, hash(line), request_id, acted_ts, action_ref}` to its **own append-only action log** before acting. That log is the input to check 10.

Rules 1–7 are enforced by `Approved.from_wire` in Python and are normative for any other implementation. Rule 8 is what makes "signed but never included" detectable; without it, the threat model's claim against a compromised gate does not hold.

## 7. Invariants and pinning tests

| ID | Invariant | Pinning test | Mutation (`mutations/I*.diff`, applied in a throwaway checkout; suite must go red) |
|---|---|---|---|
| I1 | No `Approved` without a verifying, bound, fresh, unseen receipt | Each of §6 rules 1–7 violated individually → `GateError` | remove the `cart_hash` comparison |
| I2 | `record()` raises; never partial | unwritable path → `LogUnavailable`, no partial line; disk/memory head mismatch → raise | swap raise for return |
| I3 | Strict schema and round-trip | negative vectors (§11) each exit 2 with the check number | skip the round-trip check |
| I4 | Chain continuity and genesis | edit a byte → break at k+1; delete a line → seq gap; zero-hash prev at seq≠0 → fail; file set starting at seq 7 → exit 4 | accept zero-hash anywhere |
| I5 | Heartbeat cadence and staleness | gap > 2×heartbeat_s → reported; log older than 2×heartbeat_s → `stale` | drop staleness |
| I6 | Anchor fork, cadence, and clock bound | two receipts at one seq → `fork`; no anchor for > anchor_max_s → `anchor_gap`; `record.ts` > `sink_ts`+60 s → fail | drop the cadence check |
| I7 | Log is the oracle for tests | harness run where the stub returns approve but logs reject → run fails on diff; consumer action not in log → `unlogged_approval` | read decisions from HTTP responses instead of the log |
| I8 | No text channel | static: every `str` in `Record` has a regex or enum; grep test | remove one regex |
| I9 | Boot self-check | corrupt last line → `__init__` raises; wrong keyring → raises; trailing partial line → discarded with `R_BOOT_TRUNCATED` | disable the boot verify |
| I10 | Stub gate cannot approve without the log | delete the `record()` call in `gate-stub` → its suite fails (every request rejects) | — (this *is* the mutation) |
| I11 | Domain separation | anchor-submission signature presented as record signature → fails | use one domain |
| I12 | Software signer refuses outside dev | `SoftwareSigner()` without `AUDITTRAIL_DEV=1` → `RuntimeError` | remove the guard |
| I13 | No key material exposure | grep test over `audittrail-log` source and logs (exempting `spec/` test keys); `VaultTransitSigner` has no export path | — |
| I14 | Key rotation closes the old key | record signed by old `kid` after its `valid_to_seq` → fail; consumer refuses a retired `kid` after grace | ignore windows |
| I15 | Mutations apply | each `mutations/*.diff` applies cleanly to HEAD; a refactor that disarms a mutation fails CI | — |

## 8. Ref interface (v0.2, shape only)

```python
class Oracle(Protocol):
    def lookup(self, key: OracleKey) -> OracleValue | Unavailable: ...

class Policy(Protocol):   # Cedar-shaped
    def evaluate(self, principal: Actor, action: Action, resource: Resource, context: Context) -> Allow | Deny: ...

def ref(cart: Candidate, actor: Actor, oracle: Oracle, policy: Policy, log: Log) -> Receipt:
    # Deny → record(reject). Unavailable/timeout → record(reject).
    # constant-time compare cart.value to oracle value; mismatch → record(reject).
    # match → record(approve). The caller builds Approved.from_wire with its own Candidate.
```

The ref never accepts `Untrusted`. `Candidate` is produced by a strict parser owned by the caller.

Typestate packages (v0.2) ship `Untrusted → Candidate → Validated` for Python, TypeScript, and Rust. The wire-level requirement on all of them is the same: `Candidate.canonical_bytes()` reproduces the `cart_hash` vectors, and `Validated` has no constructor other than the §6 consumer rules. Language-level enforcement is strongest in Rust and weakest in Python; each package's README states what its language cannot enforce.

## 9. Deployment topology (compose demo)

### 9.1 Services

`init` (one-shot: generates dev keypair into Vault, writes keyring to a volume, creates the MinIO bucket with object locking and a PutObject-only access key), `vault` (dev mode, transit engine), `minio` (the `anchor-sink`), `gate-stub`, `oracle-stub`, `mock-model`, `consumer-stub`, `locust-master`, `locust-worker`, `verifier` (one-shot, `depends_on: locust-master: condition: service_completed_successfully`).

`make demo` runs `docker compose up --abort-on-container-exit --exit-code-from verifier` with a 90-second schedule. Logs and run artifacts live on a named volume; `make demo` copies `runs/<id>.sqlite` and the verifier report out. Images are pinned by **manifest-list** digest (multi-arch).

### 9.2 Networks (the point of the compose file)

| Network | Members | Rule |
|---|---|---|
| `agent-net` | `mock-model`, `gate-stub` | the model side reaches only the gate |
| `oracle-net` | `gate-stub`, `oracle-stub` | only the gate reaches the oracle |
| `anchor-net` | `gate-stub`, `minio` | gate appends; nothing else |
| `signer-net` | `gate-stub`, `vault` | gate asks for signatures; nothing else |
| `consumer-net` | `gate-stub`, `consumer-stub` | receipts flow gate → consumer |
| `test-net` | `locust-*`, `gate-stub`, `consumer-stub`, `verifier`, `init` | harness drives; verifier reads volumes read-only |

`mock-model` has no route to `oracle-stub`, `minio`, `vault`, or `consumer-stub`. A CI test parses the compose file and asserts these absences.

### 9.3 Image hygiene

Base images pinned by manifest-list digest. No secrets in images; `init` creates them at run time. `AUDITTRAIL_DEV=1` is set explicitly in the compose file so the production posture is the default elsewhere. SBOM and cosign signing are v0.2.

### 9.4 Isolation statement (verbatim in README)

> The compose topology demonstrates reach constraints. It is not a security boundary. Containers share the host kernel. Deploying the agent or any document renderer in production requires a VM-class boundary (Firecracker, gVisor, Kata) and the hardening profile in `deploy/hardening.md`.

## 10. Threat model

| Attacker | Capability | What v0.1 delivers | Mechanism |
|---|---|---|---|
| A1 Document/prompt author | makes the agent request anything | nothing directly; request and decision are attributable | §3, §4 |
| A2 Compromised consumer | acts with its own authority | cannot forge approvals; cannot replay one approval for another cart or twice; its own actions are in its action log | §6 rules 2, 5, 7, 8 |
| A3 Compromised gate | signs anything going forward | cannot rewrite past the last anchor; cannot remove or overwrite anchors; fork detectable; **unlogged approvals detectable by reconciliation**; fabricated timestamps bounded by sink clock; exposure window bounded by `anchor_max_s` | §3.7, §5 checks 8 and 10, §12.1 |
| A4 Insider with write to log storage | edits/deletes lines | chain + genesis pin + anchors + reconciliation | §5 checks 3, 4, 8, 10 |
| A5 Friday-afternoon developer | relaxes a rule | boot self-check against the published verifier; verifier in a separate package; mutation diffs in CI; strict round-trip | §4, §7 |
| A6 Supply chain | tampered dependency/image | pinned digests; vectors from an independent implementation | §9.3, §11 |

Out of scope: collusion of gate owner + sink owner + verifier-package owner; physical access; availability attacks on the sink beyond `anchor_max_s` (past which the gate stops approving — a deliberate denial-of-service exposure in exchange for a bounded rewrite window).

## 11. Conformance vectors (`spec/`)

Produced by an implementation that is **not** the Python under test (a ~100-line Go tool using a JCS library and `crypto/ed25519`), committed with a SHA-256 manifest; CI fails if any vector changes without a spec version bump.

- Positive: genesis `boot`, decisions (approve/reject), heartbeat, anchor, rotation across two keys, a rotation across two files; each with `line`, `hash`, and the signature produced from the **published test seed** (Ed25519 is deterministic, so a second implementation proves it signs bit-identically).
- Negative: duplicate key, `1.0`, `1e3`, `-0`, int ≥ 2^53, extra field, missing field, unknown reason, non-ASCII, unpaired surrogate escape, BOM, CRLF, trailing space, unsorted keys, zero-hash `prev` at seq 3, wrong domain, retired `kid`, nested value (an object where an integer belongs, depth 2; check 2), nested too deep (depth 6; check 1), line too long (one byte over the §3.2 maximum; check 1); each with expected check number and exit code.
- Anchor submission and sink receipt under their domains.
- A keyring file and a reasons file.
- `spec/` is exempt from the I13 private-key grep, explicitly.

## 12. Decisions (settled by review)

1. **Anchor sink unavailable:** `record()` continues until `anchor_max_s` (default 900 s) since the last successful anchor, then raises. The verifier independently reports `anchor_gap`. Bounded exposure in exchange for keeping the sink off the per-decision latency path.
2. **Algorithm:** Ed25519 only in `v == 1`. Both reviewers doubted that AWS KMS offers Ed25519; checked against the KMS key-spec reference on 2026-10-10: it does (`ECC_NIST_EDWARDS25519`, signing only). A `KmsSigner` **must** use signing algorithm `ED25519_SHA_512` with `MessageType: RAW` (pure Ed25519, deterministic, reproduces the vectors) and **must never** use `ED25519_PH_SHA_512` (HashEdDSA, a different scheme that will not verify under RFC 8032 pure Ed25519). Vault Transit (`ed25519` key type, sign-only policy) is the reference non-exporting signer because the demo needs no cloud account. ECDSA is not in `v == 1`; if ever needed it is a schema bump.
3. **Per-record signatures:** kept. Consumer-held receipts require them; anchors are the only checkpoint.
4. **`input_ref`:** kept, as a forensic name; README disclaimer.
5. **Rekor:** v0.2; `proof` field reserved now so it is not a schema break.
6. **Hash includes `sig`:** yes (deterministic signatures make this well-defined); the chain commits to the signer.
7. **NFC / non-ASCII:** removed; forbidden by regex.
8. **Performance:** "1M in 60 s" replaced by a CI benchmark (records/s on a named runner, ≥ 10k/s on 100k records) that reports, not gates.

## 13. Acceptance criteria for v0.1

- I1–I15 pass; every mutation diff applies and turns the suite red.
- `audittrail-verify` installed into a fresh virtualenv with only its declared dependencies verifies all positive vectors (exit 0) and rejects every negative vector with the expected check number.
- A fresh clone on a clean CI runner: `make demo` exits 0, produces `runs/<id>.sqlite` and a verifier report with exit 0, and the compose network-absence test passes.
- `gate-stub-go` passes the conformance test and reproduces every positive vector byte for byte.
- README carries §9.4, the threat-model table, and "what this does not do" above the fold.

## 14. Review log (2026-10-10)

Two independent reviews (security review of the spec; delivery review of the plan). Accepted and folded in: receipt binding to cart/app/log_id/freshness/single-use (critical); inclusion ≠ signing → consumer action logs + reconciler (critical); anchor-gap, staleness, exit code 4, cadence read from `boot` record; genesis pinned to seq 0, rotation by `Log` only, no re-genesis; harness holes (consumer action log ⊆ log, per-mode expected outcomes, liveness floor, classify by send time, drain before flip — see testkit section in PLAN); `boot` field and record type; keyring windows, rotation record, one algorithm per schema; line-is-canonical with round-trip check, hash includes sig, non-ASCII forbidden; regexes for every string; anchor/heartbeat type rules; boot self-check scope; torn-write and `fsync(dir)` rules; `AnchorReceipt` as JCS with sink timestamp used; `Approved.from_wire`; threat-model claims tied to mechanisms; reasons sections; exit-code semantics; heartbeat from the request loop with `since_hb`; perf target → benchmark. **Checked rather than accepted:** both reviewers asserted AWS KMS lacks Ed25519; the KMS documentation says otherwise (§12.2). The spec keeps Vault as the reference signer for the reason that survives (no cloud account needed) and allows KMS as an optional adapter with the RAW-vs-prehash constraint stated.

Rejected or modified: "drop per-record signatures" — not proposed by either reviewer, kept; "Rekor in v0.1" — stretch, field reserved; the suggestion that the consumer read the gate log directly for inclusion — rejected in favor of the action log + reconciler, because giving every consumer read access to the log widens the log's reader set and the reconciler keeps verification in one package.

## 14a. Post-vector clarifications (2026-10-11)

Three gaps surfaced by generating the §11 vectors, all resolved in favour of what the generator did: the record hash excludes the trailing `\n` (§3.2); a genesis `boot` record carries the zero-hash in `cart_hash` and non-decision records carry `app: gate` (§3.4); the verifier takes `--now` so fixed-date vectors can exit 0 (§5). None of these change any committed vector.

## 14b. Post-debate clarifications (2026-10-11)

Nesting depth and line length were silent in §3 and §5; the round-two adversarial review of the `Record` implementation showed two conforming parsers disagreeing on the check number in a window set by their own depth limits, which move between interpreter releases. Settled after a three-advocate debate and a judge (issue #11): depth bound 5 on record lines and on v0.2 Candidates, a derived line length, both counted over bytes before parsing. The number is a human-readability bound, not a parser default: this data moves to and from a model and must stay glanceable by a human. The three negative vectors named in §11 are added by the vector tool in the implementation change that follows, with the version bump that requires.

## 15. Sources

- RFC 8785 JCS — https://www.rfc-editor.org/rfc/rfc8785
- RFC 8032 Ed25519 — https://www.rfc-editor.org/rfc/rfc8032
- Certificate Transparency — https://certificate.transparency.dev/howctworks/
- Sigstore Rekor — https://docs.sigstore.dev/logging/overview/
- HashiCorp Vault Transit — https://developer.hashicorp.com/vault/docs/secrets/transit
- AWS KMS key spec reference (Ed25519 support) — https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html
- MinIO Object Locking — https://min.io/docs/minio/linux/administration/object-management/object-retention.html
- AWS S3 Object Lock — https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- Locust custom load shapes — https://docs.locust.io/en/stable/custom-load-shape.html
- "Parsing JSON is a Minefield" — https://seriot.ch/projects/parsing_json.html
