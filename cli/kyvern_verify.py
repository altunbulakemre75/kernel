import argparse
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from services.decision.anchors import anchors_path_for, check_anchors, read_receipts
from services.decision.audit_chain import (
    Keyring,
    check_policy_binding,
    describe_chain_failure,
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

def load_pubkey(path: str) -> Any:
    try:
        with open(path, "rb") as f:
            pub_bytes = f.read()
        return serialization.load_pem_public_key(pub_bytes)
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
    if sys.stdout.encoding.lower() != "utf-8":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    if sys.stderr.encoding.lower() != "utf-8":
        try:
            sys.stderr.reconfigure(encoding="utf-8")
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
                "decisions": [], "policy_version_id": None, "errors": ["No decisions found in chain file"]
            }))
        else:
            print(f"{RED_CROSS} No decisions found in chain file.")
        sys.exit(1)
        
    public_key = Keyring([load_pubkey(p) for p in args.pubkey])

    is_valid_chain, broken_idx = verify_chain(decisions, public_key)
    errors = []
    failure_reason = None

    if not is_valid_chain:
        failure_reason = describe_chain_failure(decisions, broken_idx, public_key)
        errors.append(f"Chain integrity broken at index {broken_idx}: {failure_reason}")

    key_ids = sorted({d["key_id"] for d in decisions if d.get("key_id")})
    decision_count = sum(1 for d in decisions if record_type_of(d) == "decision")
    event_count = len(decisions) - decision_count

    policies = []
    policy_load_error = None
    for path in args.policy:
        try:
            policies.append(load_policy(path))
        except Exception as e:
            policy_load_error = f"Failed to load policy file {path}: {e}"
            errors.append(policy_load_error)
    policy_check = check_policy_binding(decisions, policies)
    policy_matches = policy_load_error is None and policy_check.ok
    if policy_load_error is None and not policy_check.ok:
        errors.append(f"Policy check failed: {policy_check.reason()}")
    policy_hash = policies[0].version_id if policies else None

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
        for policy, path in zip(policies, args.policy, strict=True):
            print(
                f"{GREEN_CHECK} Policy match: {policy.version_short} ({_policy_label(path)}): "
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
        print(f"  Anchors: none (no {anchors_path.name})")
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
        else:
            action = str(d.get("action", "UNKNOWN")).upper()
            rule_id = d.get("roe_reference", "unknown")
            if rule_id is None:
                rule_id = "None"
            guardrails = d.get("guardrails_triggered", [])
            g_str = "[" + ", ".join(guardrails) + "]"
            print(f"  [{i}] {time_str}  action={action:<7} rule_id={rule_id:<6} guardrails={g_str}")
        if args.verbose:
            print(f"      {json.dumps(d)}")

    if all_valid and len(policies) == 1:
        print(f"\nAudit hash: {policy_hash[:16]} (verifiable against deployed policy)")
        
    sys.exit(0 if all_valid else 1)

if __name__ == "__main__":
    main()
