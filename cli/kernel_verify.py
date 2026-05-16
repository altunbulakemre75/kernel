import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization

from services.decision.audit_chain import verify_chain, verify_decision_against_policy
from services.decision.policy_loader import load_policy

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
        with open(path, "r", encoding="utf-8") as f:
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
    parser.add_argument("--policy", required=True, help="path to policy YAML")
    parser.add_argument("--pubkey", required=True, help="path to PEM-encoded Ed25519 public key")
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
        
    public_key = load_pubkey(args.pubkey)
    
    is_valid_chain, broken_idx = verify_chain(decisions, public_key)
    errors = []
    
    if not is_valid_chain:
        errors.append(f"Chain integrity broken at index {broken_idx}")
        
    policy_matches = True
    mismatched_policy_idx = None
    policy_reason = None
    
    for idx, d in enumerate(decisions):
        is_match, reason = verify_decision_against_policy(d, args.policy, public_key)
        if not is_match:
            policy_matches = False
            mismatched_policy_idx = idx
            policy_reason = reason
            errors.append(f"Policy mismatch at index {idx}: {reason}")
            break
            
    try:
        policy_obj = load_policy(args.policy)
        policy_hash = policy_obj.version_id
    except Exception as e:
        policy_obj = None
        policy_hash = None
        errors.append(f"Failed to load policy file: {e}")
        policy_matches = False

    all_valid = is_valid_chain and policy_matches
    
    if args.json:
        out = {
            "chain_valid": is_valid_chain,
            "policy_match": policy_matches,
            "signature_valid": is_valid_chain,
            "decisions": decisions,
            "policy_version_id": policy_hash,
            "errors": errors
        }
        print(json.dumps(out, indent=2))
        sys.exit(0 if all_valid else 1)
        
    if is_valid_chain:
        print(f"{GREEN_CHECK} Chain integrity: VALID ({len(decisions)} decisions, all signed)")
    else:
        print(f"{RED_CROSS} Chain integrity: INVALID (Broken at index {broken_idx})")
        
    if policy_matches and policy_hash:
        try:
            mtime = os.path.getmtime(args.policy)
            mtime_dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
            mtime_str = mtime_dt.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            mtime_str = "unknown date"
        
        policy_basename = os.path.basename(args.policy)
        short_hash = policy_hash[:16]
        print(f"{GREEN_CHECK} Policy match: {short_hash} ({policy_basename} @ {mtime_str})")
    else:
        print(f"{RED_CROSS} Policy match: FAILED")
        if mismatched_policy_idx is not None:
            print(f"  Reason: Decision [{mismatched_policy_idx}] mismatch - {policy_reason}")
        elif not policy_hash:
            print("  Reason: Failed to load policy file")
            
    if is_valid_chain:
        print(f"{GREEN_CHECK} Signature verification: PASSED (Ed25519)")
    else:
        print(f"{RED_CROSS} Signature verification: FAILED")

    print("\nDecision summary:")
    for i, d in enumerate(decisions):
        time_str = format_time(d.get("timestamp_iso", ""))
        action = str(d.get("action", "UNKNOWN")).upper()
        rule_id = d.get("roe_reference", "unknown")
        if rule_id is None:
            rule_id = "None"
        guardrails = d.get("guardrails_triggered", [])
        g_str = "[" + ", ".join(guardrails) + "]"
        
        print(f"  [{i}] {time_str}  action={action:<7} rule_id={rule_id:<6} guardrails={g_str}")
        if args.verbose:
            print(f"      {json.dumps(d)}")

    if all_valid and policy_hash:
        print(f"\nAudit hash: {policy_hash[:16]} (verifiable against deployed policy)")
        
    sys.exit(0 if all_valid else 1)

if __name__ == "__main__":
    main()
