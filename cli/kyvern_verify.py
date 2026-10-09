import argparse
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from services.decision.anchors import anchors_path_for, check_anchors, read_receipts
from services.decision.audit_chain import (
    Keyring,
    check_policy_binding,
    describe_chain_failure,
    load_public_key,
    record_type_of,
    verify_chain,
)
from services.decision.policy_loader import load_policy
from services.decision.rfc3161_anchor import RFC3161Anchor, load_roots

try:
    import colorama
    colorama.init(autoreset=True)
    GREEN_CHECK = f"{colorama.Fore.GREEN}✓{colorama.Style.RESET_ALL}"
    RED_CROSS = f"{colorama.Fore.RED}✗{colorama.Style.RESET_ALL}"
except ImportError:
    GREEN_CHECK = "✓"
    RED_CROSS = "✗"

def format_time(ts: str) -> str:
    if not ts:
        return "Unknown"
    if not isinstance(ts, str):  # a tampered record may hold any JSON value
        return "Invalid"
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%H:%M:%S")
    except Exception:
        return ts[:8]

def load_jsonl(path: str) -> list[dict[str, Any]]:
    decisions = []
    try:
        with open(path, encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if line:
                    try:
                        decisions.append(json.loads(line))
                    except json.JSONDecodeError:
                        print(f"{RED_CROSS} Error reading {path}: line {line_no} is not valid JSON")
                        sys.exit(1)
    except FileNotFoundError:
        print(f"{RED_CROSS} File not found: {path}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED_CROSS} Error reading {path}: {e}")
        sys.exit(1)
    return decisions

def load_pubkey(path: str) -> Ed25519PublicKey:
    try:
        return load_public_key(path)
    except FileNotFoundError:
        print(f"{RED_CROSS} Public key file not found: {path}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED_CROSS} Invalid public key in {path}: {e}")
        sys.exit(1)

def _policy_label(path: str) -> str:
    """Policy file name and modification time, for the human-readable output."""
    try:
        mtime = datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc)
        when = mtime.strftime("%Y-%m-%d %H:%M UTC")
    except OSError:
        when = "unknown date"
    return f"{os.path.basename(path)} @ {when}"

def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        # Not isinstance(io.TextIOWrapper): on Windows colorama wraps the streams
        # and passes reconfigure() through to them.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None and (stream.encoding or "").lower() != "utf-8":
            try:
                reconfigure(encoding="utf-8")
            except Exception:
                pass
            
    parser = argparse.ArgumentParser(description="Verify a cryptographically signed decision chain.")
    parser.add_argument("chain_file", help="path to JSONL file with decisions")
    parser.add_argument(
        "--policy", required=True, action="append",
        help="path to a policy YAML; repeat for a chain that spans policy updates",
    )
    parser.add_argument(
        "--pubkey", required=True, action="append",
        help="path to a PEM-encoded Ed25519 public key; repeat for chains signed by several keys",
    )
    parser.add_argument(
        "--anchors", default=None,
        help="anchor receipts JSONL (default: <chain stem>.anchors.jsonl next to the chain, if present)",
    )
    parser.add_argument(
        "--require-anchors", action="store_true",
        help="fail unless the chain has at least one valid anchor receipt: without "
             "receipts, entries deleted from the end of the chain cannot be detected",
    )
    parser.add_argument(
        "--tsa-root", action="append", default=None,
        help="PEM file with trusted TSA root certificate(s); repeatable (default: certifi bundle)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="show full payload of each decision")
    parser.add_argument("--json", action="store_true", help="output machine-readable JSON instead of human format")
    
    args = parser.parse_args()
    
    decisions = load_jsonl(args.chain_file)
    if not decisions:
        if args.json:
            print(json.dumps({
                "chain_valid": False, "policy_match": False, "signature_valid": False,
                "decisions": [], "decision_count": 0, "runtime_event_count": 0,
                "policy_version_id": None, "policy_version_ids": [],
                "decisions_per_policy": {}, "unbound_decisions": [],
                "unknown_policy_decisions": {}, "key_ids": [], "reason": None,
                "anchors": None, "anchors_required": args.require_anchors,
                "errors": ["No decisions found in chain file"],
            }))
        else:
            print(f"{RED_CROSS} No decisions found in chain file.")
        sys.exit(1)
        
    public_key = Keyring([load_pubkey(p) for p in args.pubkey])

    is_valid_chain, broken_idx = verify_chain(decisions, public_key)
    errors = []
    failure_reason = None

    if not is_valid_chain:
        assert broken_idx is not None  # verify_chain names the failing entry
        failure_reason = describe_chain_failure(decisions, broken_idx, public_key)
        errors.append(f"Chain integrity broken at index {broken_idx}: {failure_reason}")

    key_ids = sorted({d["key_id"] for d in decisions if isinstance(d.get("key_id"), str) and d["key_id"]})
    decision_count = sum(1 for d in decisions if record_type_of(d) == "decision")
    event_count = len(decisions) - decision_count

    unique_policies: dict[str, Any] = {}
    policy_load_error = None
    for path in args.policy:
        try:
            policy = load_policy(path)
        except Exception as e:
            policy_load_error = f"Failed to load policy file {path}: {e}"
            errors.append(policy_load_error)
            continue
        # The same policy given twice (or two files with the same content) counts once.
        unique_policies.setdefault(policy.version_id, policy)
    policies = list(unique_policies.values())
    policy_check = check_policy_binding(decisions, policies, broken_at=broken_idx)
    policy_matches = policy_load_error is None and policy_check.ok
    if policy_load_error is None and not policy_check.ok:
        errors.append(f"Policy check failed: {policy_check.reason()}")
    # One version id only when one policy was given; policy_version_ids lists them all.
    policy_hash = policies[0].version_id if len(policies) == 1 else None

    anchors_path = Path(args.anchors) if args.anchors else anchors_path_for(Path(args.chain_file))
    anchor_report = None
    anchors_ok = True
    if anchors_path.exists():
        anchor_report = check_anchors(
            decisions,
            read_receipts(anchors_path),
            {RFC3161Anchor.name: RFC3161Anchor(roots=load_roots(args.tsa_root))},
        )
        for failure in anchor_report.failures:
            errors.append(f"Anchor check failed: {failure}")
        anchors_ok = not anchor_report.failures
    elif args.anchors:
        errors.append(f"Anchors file not found: {anchors_path}")
        anchors_ok = False
    # Signatures and hash links cannot show that entries were deleted from the end of
    # the chain; a receipt for an entry that is gone can.
    anchors_missing = args.require_anchors and (anchor_report is None or anchor_report.valid == 0)
    if anchors_missing:
        errors.append(
            "Anchors required (--require-anchors) but "
            + (f"no receipts file {anchors_path}" if anchor_report is None else "no receipt is valid")
        )
        anchors_ok = False

    all_valid = is_valid_chain and policy_matches and anchors_ok

    if args.json:
        out = {
            "chain_valid": is_valid_chain,
            "policy_match": policy_matches,
            "signature_valid": is_valid_chain,
            "decisions": decisions,
            "decision_count": decision_count,
            "runtime_event_count": event_count,
            "policy_version_id": policy_hash,
            "policy_version_ids": [p.version_id for p in policies],
            "decisions_per_policy": policy_check.per_policy,
            "unbound_decisions": policy_check.unbound,
            "unknown_policy_decisions": {str(i): v for i, v in policy_check.unknown.items()},
            "key_ids": key_ids,
            "reason": failure_reason,
            "anchors": asdict(anchor_report) if anchor_report else None,
            "anchors_required": args.require_anchors,
            "errors": errors
        }
        print(json.dumps(out, indent=2))
        sys.exit(0 if all_valid else 1)
        
    counts = f"{decision_count} decisions"
    if event_count:
        counts += f", {event_count} runtime events"
    if is_valid_chain:
        print(f"{GREEN_CHECK} Chain integrity: VALID ({counts}, all signed)")
    else:
        print(f"{RED_CROSS} Chain integrity: INVALID (Broken at index {broken_idx}: {failure_reason})")

    if policy_matches:
        for policy in policies:
            print(
                f"{GREEN_CHECK} Policy match: {policy.version_short} ({_policy_label(policy.path)}): "
                f"{policy_check.per_policy[policy.version_id]} decisions"
            )
    else:
        print(f"{RED_CROSS} Policy match: FAILED")
        print(f"  Reason: {policy_load_error or policy_check.reason()}")
            
    if is_valid_chain:
        print(f"{GREEN_CHECK} Signature verification: PASSED (Ed25519)")
    else:
        print(f"{RED_CROSS} Signature verification: FAILED")

    if anchor_report is None:
        if anchors_missing:
            print(f"{RED_CROSS} Anchors: REQUIRED, none found (no {anchors_path.name})")
        else:
            print(f"  Anchors: none (no {anchors_path.name})")
    elif anchors_missing and not anchor_report.failures:
        print(f"{RED_CROSS} Anchors: REQUIRED, none valid in {anchors_path.name}")
    elif anchor_report.failures:
        print(f"{RED_CROSS} Anchors: FAILED")
        for failure in anchor_report.failures:
            print(f"  {failure}")
    else:
        line = f"{GREEN_CHECK} Anchors: {anchor_report.valid} valid"
        if anchor_report.latest_index is not None:
            line += (
                f"; latest covers chain_index {anchor_report.latest_index} at "
                f"{anchor_report.latest_time}; {anchor_report.unanchored_tail} later "
                "entries not yet anchored"
            )
        print(line)

    print("\nDecision summary:")
    for i, d in enumerate(decisions):
        time_str = format_time(d.get("timestamp_iso", ""))
        if record_type_of(d) == "runtime_event":
            print(f"  [{i}] {time_str}  event={d.get('event_type')} source={d.get('source')}")
        elif d.get("record_type") == "decision":  # recorded with record_decision()
            action = str(d.get("action", "UNKNOWN")).upper()
            print(
                f"  [{i}] {time_str}  action={action:<8} rule_id={d.get('rule_id')} "
                f"source={d.get('source')}"
            )
        else:
            # str() throughout: a tampered record may hold any JSON value in these fields.
            action = str(d.get("action", "UNKNOWN")).upper()
            rule_id = str(d.get("roe_reference", "unknown"))
            guardrails = d.get("guardrails_triggered") or []
            if not isinstance(guardrails, list):
                guardrails = [guardrails]
            g_str = "[" + ", ".join(str(g) for g in guardrails) + "]"
            print(f"  [{i}] {time_str}  action={action:<7} rule_id={rule_id:<6} guardrails={g_str}")
        if args.verbose:
            print(f"      {json.dumps(d)}")

    if all_valid and policy_hash:
        print(f"\nAudit hash: {policy_hash[:16]} (verifiable against deployed policy)")
        
    sys.exit(0 if all_valid else 1)

if __name__ == "__main__":
    main()
