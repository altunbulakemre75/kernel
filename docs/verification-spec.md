# Chain format and verification (spec v1)

> Status: describes Kyvern 0.5. Anchor statement version `kyvern_anchor: 1`.

This document is for anyone who wants to check a Kyvern chain **without
Kyvern**: an auditor's own script, another logging system, a verifier in a
language other than Python. It says what is in the files, which bytes are
hashed and signed, and the checks `kyvern-verify` runs, in enough detail to
write an independent verifier. The [test vectors](#test-vectors) at the end
let you check your implementation byte for byte.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## Files

| File | Content |
|------|---------|
| `chain.jsonl` | The chain: one record per line, UTF-8, `\n` line ends |
| `<chain stem>.anchors.jsonl` | RFC 3161 receipts, one per line, next to the chain (`chain.anchors.jsonl`) |
| `*.pub` | Ed25519 public keys, PEM (`SubjectPublicKeyInfo`) |
| policy YAML | The decision policy, any YAML mapping with a `rules:` list |

Each line of `chain.jsonl` is one JSON object. Empty lines are ignored. A line
that is not a JSON object makes the chain fail verification.

## Records

A record is a JSON object. These fields take part in verification:

| Field | Type | Meaning |
|-------|------|---------|
| `chain_index` | integer | Position in the chain: 0 for the first record, then +1 per record |
| `prev_hash` | string or null | `payload_hash` of the previous record; null for the first |
| `key_id` | string | Which key signed it (see [Keys](#keys)); absent in records written before Kyvern 0.3 |
| `payload_hash` | string | Lowercase hex SHA-256 of the record's canonical form |
| `signature` | string | Base64 (RFC 4648, with padding) Ed25519 signature of the canonical form |
| `timestamp_iso` | string | When the record says it was made: ISO 8601 with a UTC offset |
| `record_type` | string | `"runtime_event"`, `"decision"`, or absent (a decision from Kyvern's own engine) |
| `policy_version_id` | string or null | The policy a decision was made under (see [Policy binding](#policy-binding)) |

Every other field (`action`, `source`, `reasoning`, `inputs`, ...) is covered
by the signature but not interpreted by verification. A verifier MUST keep
fields it does not know: they are part of the signed bytes.

## Canonical form

The canonical form of a record is the bytes that are hashed and signed:

1. Remove the `signature` and `payload_hash` members. Every other member,
   including `key_id`, `prev_hash` and `chain_index`, stays.
2. Serialise as JSON, exactly as Python's
   `json.dumps(obj, separators=(",", ":"), sort_keys=True)` does:
    - no whitespace between tokens;
    - object members sorted by key, comparing keys by Unicode code point, at
      every level of nesting;
    - strings escape `"` and `\` as `\"` and `\\`, the control characters
      `\b \f \n \r \t` by name, other characters below U+0020 and **every
      character above U+007E** as `\uXXXX` (lowercase hex), and characters
      outside the Basic Multilingual Plane as a UTF-16 surrogate pair
      (`"🤖"` → `"\ud83e\udd16"`); `/` is not escaped;
    - `true`, `false`, `null`;
    - integers in decimal, any size;
    - other numbers as Python's `repr(float)`: the shortest digits that
      round-trip, with a `.0` for integral values (`2.0`), and exponent
      notation when the decimal exponent is below -4 or at least 16, with a
      sign and at least two exponent digits (`1e-05`, `1e+16`).
3. Encode as UTF-8 (after step 2 the bytes are all ASCII).

This is **not** RFC 8785 (JCS): JCS sorts by UTF-16 code units, writes
non-ASCII characters unescaped and formats numbers the ECMAScript way. Do not
substitute it.

Kyvern 0.5 writes the record lines themselves with
`json.dumps(record, separators=(",", ":"))`. Re-serialise the parsed record
as above rather than hashing the line as found in the file. A record MUST NOT
contain NaN or infinities, which JSON cannot represent; Kyvern refuses to
append such a record (from 0.5.1).

## Keys

Signatures are Ed25519 (RFC 8032) over the canonical form, not over its hash.

`key_id` is the first 16 hex characters of the SHA-256 of the raw 32-byte
public key. A verifier is given a set of trusted public keys (`--pubkey`,
repeatable):

- a record **with** `key_id` MUST verify under the trusted key with that id;
  a `key_id` that matches no trusted key, or is not a string, fails;
- a record **without** `key_id` (written before Kyvern 0.3) MAY verify under
  any trusted key.

## Verifying a chain

```text
expected_index = records[0].chain_index      # MUST be an integer (not a boolean)
prev = null                                   # or the payload_hash before a sub-range
for i, r in enumerate(records):
    r.chain_index == expected_index           else fail at i: "chain_index gap"
    r.prev_hash == prev                       else fail at i: "broken prev_hash link"
    c = canonical(r)
    r.payload_hash == hex(sha256(c))          else fail at i: "bad signature"
    ed25519_verify(key_for(r), base64(r.signature), c)
                                              else fail at i: "bad signature"
                                              (or "signed by unknown key <id>")
    prev = r.payload_hash
    expected_index += 1
```

The chain is valid when every record passes. Report the first failing
position; every later record is unverified. An empty chain is not a valid
chain to report on: `kyvern-verify` fails it.

A sub-range that does not start at the first record is verified the same way
with `prev` set to the `payload_hash` of the record before it, which that
check then trusts.

## Policy binding

A policy's version id is the lowercase hex SHA-256 of the canonical form (as
[above](#canonical-form), with no members removed) of the policy YAML parsed
as data. Comments, key order and formatting do not change it. Kyvern parses
the YAML with PyYAML's `safe_load` (YAML 1.1); keep policies to strings,
numbers, booleans, null, lists and mappings so that every YAML parser reads
the same data.

Given one or more policies, every **decision** (a record whose `record_type`
is not `"runtime_event"`) MUST have a `policy_version_id` equal to the
version id of one of them. Runtime events are not checked. A chain with no
decision fails the check, since nothing in it is bound to a policy. When the
chain itself fails verification, the policy ids it records are unverified.

## Anchors

An anchor is independent evidence that a record existed at a given time.
Kyvern 0.5 has one kind, `rfc3161`: a timestamp token from an RFC 3161 Time
Stamping Authority (TSA).

**Statement.** The bytes an anchor certifies for record `n` are the canonical
form of

```json
{"chain_index": n, "kyvern_anchor": 1, "payload_hash": "<payload_hash of record n>"}
```

that is, `{"chain_index":n,"kyvern_anchor":1,"payload_hash":"..."}`.

**Request.** `kyvern-anchor` sends an RFC 3161 `TimeStampReq` whose message
imprint is the SHA-256 of the statement, with a random nonce and
`certReq = true`. Only that hash leaves the machine.

**Receipt.** Each line of the receipts file is a JSON object:

| Field | Meaning |
|-------|---------|
| `anchor` | `"rfc3161"` |
| `chain_index` | The anchored record's position (integer) |
| `payload_hash` | The anchored record's `payload_hash` (string) |
| `anchored_at` | The token's `genTime`, as `YYYY-MM-DDTHH:MM:SSZ` (informational) |
| `tsa_url` | Where the token came from (informational) |
| `token` | Base64 of the DER `TimeStampResp` as the TSA returned it |

**Checking a receipt.** For each line of the receipts file:

1. It MUST be a JSON object with an integer `chain_index` and a string
   `payload_hash`, and its `anchor` MUST be a known kind. Otherwise it is a
   failure ("malformed", "not JSON", "unknown anchor type").
2. The chain MUST contain a record with that `chain_index` ("chain entry n is
   missing" otherwise: entries were deleted).
3. The record's `payload_hash` MUST equal the receipt's ("does not match the
   anchored hash" otherwise: the record was rewritten after it was anchored,
   whoever holds the signing key).
4. The token MUST verify: its message imprint is the SHA-256 of the
   statement built from the receipt, and its signature chains to a trusted
   TSA root. The time anchored is the token's `genTime`, not `anchored_at`.

A valid receipt for record `n` covers records `0..n`, which are hash-linked to
it. Records after the latest valid receipt are not covered ("not yet
anchored").

**Required anchors.** Signatures alone cannot show that records were deleted
from the end of a chain: the shorter chain is still valid. With
`--require-anchors`, a chain with no valid receipt fails.

**Maximum lag.** A receipt proves when a record existed, not the time the
record claims. With `--max-lag D`, for every covered record, let `t` be its
`timestamp_iso` and `T` the earliest `genTime` among the valid receipts that
cover it. The record fails if `T - t > D` (anchored long after the time it
claims: possibly backdated) or `t - T > D` (dated after the receipt that
covers it, impossible on correct clocks). A covered record without a usable
UTC `timestamp_iso` fails. Records that no receipt covers are not measured.

## What verification shows

- **Valid chain:** every record is as it was signed, in order, by a trusted
  key. Anyone holding a trusted signing key can still write a valid chain.
- **Valid receipts:** the anchored records existed, as they are now, at the
  receipt's time. That holds even against someone who holds the signing
  key.
- **Within `--max-lag`:** the covered records were not dated more than the
  lag away from the time they demonstrably existed.

Verification does not show that every decision the system made was recorded,
or that a record's content is true. The receipts file is the evidence for
the second and third points: keep a copy of it off the machine that writes
the chain.

## Test vectors

The vectors are in `tests/fixtures/spec/` and are rebuilt by
`scripts/generate_spec_vectors.py`. `tests/test_spec_vectors.py` checks that
the implementation reproduces them and that the values below are current.

**Test key.** Ed25519 private key seed `000102…1f` (the bytes 0 to 31). It is
published: never trust it for real records.

<!-- vector:public-key -->
```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=
-----END PUBLIC KEY-----
```

<!-- vector:key-id -->
```text
56475aa75463474c
```

**Policy.** `tests/fixtures/spec/policy.yaml`; its version id:

<!-- vector:policy-version-id -->
```text
f1c435cc1c0d58c81db250c0406f55d87a694825e30b6a99cc7ad6ed55e5531d
```

**Record 0.** Canonical form (one line; note `\u00e9` for `é`):

<!-- vector:canonical-0 -->
```text
{"action":"stop","chain_index":0,"inputs":{"min_range_m":0.4,"site":"Montr\u00e9al"},"key_id":"56475aa75463474c","policy_path":"policy.yaml","policy_version_id":"f1c435cc1c0d58c81db250c0406f55d87a694825e30b6a99cc7ad6ed55e5531d","prev_hash":null,"reasoning":"obstacle at 0.4 m, closer than 0.5 m","record_type":"decision","requires_operator_approval":false,"rule_id":"stop-on-obstacle","source":"safety_controller","subject_id":"amr-01","timestamp_iso":"2026-10-07T12:00:00+00:00"}
```

<!-- vector:payload-hash-0 -->
```text
0b01a56d2a397cea67ac75305f2dd8f0b4a61c08b578571370de3bc81255392d
```

<!-- vector:signature-0 -->
```text
ZJbIjabM1N5wIfHChMXYYqzXS9ZUwIGEu/kv85ijKqvlxXhTeDoJtN/fKRSBef4ili0vSQv/UkZwO7wlrYF5AA==
```

**Record 1** links to record 0 (`prev_hash` = the hash above) and has
`payload_hash`:

<!-- vector:payload-hash-1 -->
```text
2d01cd2f2e951f06b042a84a5a0eb4e8ceb643f823f401ba3acd720a8d9e8f5b
```

**Anchor statement** for record 1, and its SHA-256 (the message imprint a
TSA signs):

<!-- vector:statement-1 -->
```text
{"chain_index":1,"kyvern_anchor":1,"payload_hash":"2d01cd2f2e951f06b042a84a5a0eb4e8ceb643f823f401ba3acd720a8d9e8f5b"}
```

<!-- vector:imprint-1 -->
```text
fcadc7d2f01f02f198e605e09b6144279d5e313692a60c6f979383728978ae9c
```

**A real receipt.** RFC 3161 tokens are not deterministic, so there is no
vector for one. `tests/fixtures/rfc3161/` holds a recorded chain with a
receipt from IdenTrust and the roots to check it. Its records are dated
about 15 minutes after the receipt, so `--max-lag 10m` fails it and
`--max-lag 1h` passes.

## Versions

`kyvern_anchor` in the anchor statement is 1. A future change to the
canonical form, the statement or the receipt fields will change this
document's version and say how older chains are verified.
