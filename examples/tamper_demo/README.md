# Tamper demo: four attacks on a robot's decision log

A warehouse robot (`amr-01`) records its own safety decisions with Kyvern, as
in [`ros2_safety_demo`](../ros2_safety_demo/): it slows down, then stops for an
obstacle, and an operator resumes it. The log is anchored with an RFC 3161 Time
Stamping Authority. Each attack below then changes a copy of the log, and
`kyvern-verify` decides.

```bash
python examples/tamper_demo/run_demo.py            # needs network for the receipts
python examples/tamper_demo/run_demo.py --offline  # attack 1 only
```

| Attack | Who | Signatures alone | Caught by |
|--------|-----|------------------|-----------|
| 1. Change STOP to CONTINUE in the file | anyone with file access | caught | Ed25519 signature |
| 2. Change STOP to CONTINUE and re-sign it and every later decision | insider with the signing key | **pass** | RFC 3161 receipt: the anchored entry no longer matches |
| 3. Delete the latest decisions | insider with the signing key | **pass** | RFC 3161 receipt: the anchored entry is missing |
| 4. Add a decision dated 30 days ago, sign it and anchor it today | insider with the signing key | **pass** | `--max-lag 1h`: anchored 30 days after its timestamp |

Recorded output (the times will differ):

```
Robot amr-01 recorded 5 safety decisions and anchored the log with an RFC 3161 Time Stamping Authority.

✓ Untouched log: verifies

✓ CAUGHT  1. Edit a decision in the file
    attack:          changes decision 2 from STOP to CONTINUE in the file
    signatures only: caught too
    kyvern-verify:   Chain integrity broken at index 2: bad signature

✓ CAUGHT  2. Insider rewrites a decision and re-signs
    attack:          changes decision 2 from STOP to CONTINUE and re-signs it and every later one
    signatures only: would PASS
    kyvern-verify:   Anchor check failed: receipt 0: chain entry 4 does not match the anchored hash (rewritten after 2026-10-09T12:47:31Z?)

✓ CAUGHT  3. Insider deletes the latest decisions
    attack:          deletes the last 2 of 5 decisions
    signatures only: would PASS
    kyvern-verify:   Anchor check failed: receipt 0: chain entry 4 is missing

✓ CAUGHT  4. Insider adds a backdated decision
    attack:          appends a decision dated 30 days ago, signs it and anchors it today
    signatures only: would PASS
    kyvern-verify:   Anchor lag: entry 5 was first anchored 30d 1s after its timestamp (2026-09-09T12:47:39.598955+00:00, receipt 2026-10-09T12:47:41Z)

4 of 4 attacks caught.
```

The demo writes every tampered copy to `--out` (default `./kyvern-tamper-demo`),
so you can run `kyvern-verify` on them yourself, and an evidence report
(`report.pdf`) for the untouched log.

What this does not show: the receipts file is the evidence for attacks 2–4.
An insider who can also delete `chain.anchors.jsonl` is stopped only if a copy
is kept off the host and the verifier runs with `--require-anchors`; see the
[threat model](../../docs/threat-model.md). Only a SHA-256 hash is sent to the
Time Stamping Authority (IdenTrust by default).
