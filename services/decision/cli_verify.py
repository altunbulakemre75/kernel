import argparse
import json
import os
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization

from services.decision.audit_chain import (
    verify_chain,
    verify_decision_against_policy,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a cryptographically signed decision chain.")
    parser.add_argument("chain_file", help="Path to JSONL file containing decisions")
    parser.add_argument("--policy", required=True, help="Path to policy YAML file")
    parser.add_argument("--pubkey", required=True, help="Path to Ed25519 public key file")
    
    args = parser.parse_args()
    
    try:
        with open(args.pubkey, "rb") as f:
            pub_bytes = f.read()
        public_key = serialization.load_pem_public_key(pub_bytes)
    except Exception as e:
        print(f"Error loading public key: {e}")
        sys.exit(1)
        
    decisions = []
    try:
        with open(args.chain_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    decisions.append(json.loads(line))
    except Exception as e:
        print(f"Error reading chain file: {e}")
        sys.exit(1)
        
    if not decisions:
        print("No decisions found in chain file.")
        sys.exit(1)
        
    is_valid_chain, broken_idx = verify_chain(decisions, public_key)
    
    if is_valid_chain:
        print(f"✓ Chain integrity: VALID ({len(decisions)} decisions, all signed)")
    else:
        print(f"✗ Chain integrity: INVALID (Broken at index {broken_idx})")
        sys.exit(1)
        
    last_decision = decisions[-1]
    is_valid_policy, reason = verify_decision_against_policy(last_decision, args.policy, public_key)
    
    policy_hash = last_decision.get("policy_version_id", "unknown")
    short_hash = policy_hash[:16] if policy_hash != "unknown" else "unknown"
    
    try:
        mtime = os.path.getmtime(args.policy)
        mtime_dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
        mtime_str = mtime_dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        mtime_str = "unknown date"
        
    policy_basename = os.path.basename(args.policy)
    
    if is_valid_policy:
        print(f"✓ Policy match: {short_hash} ({policy_basename} @ {mtime_str})")
    else:
        print(f"✗ Policy match: FAILED ({reason})")
        sys.exit(1)
        
    print("✓ Signature verification: PASSED (Ed25519)")
    print("\nDecision summary:")
    
    for i, d in enumerate(decisions):
        ts = d.get("timestamp_iso", "")
        time_str = ""
        if ts:
            try:
                if ts.endswith("Z"):
                    ts = ts[:-1] + "+00:00"
                dt = datetime.fromisoformat(ts)
                time_str = dt.strftime("%H:%M:%S")
            except Exception:
                time_str = ts[:8]
        
        action = str(d.get("action", "UNKNOWN")).upper()
        rule_id = d.get("roe_reference", "unknown")
        if rule_id is None:
            rule_id = "None"
        guardrails = d.get("guardrails_triggered", [])
        g_str = "[" + ", ".join(guardrails) + "]"
        
        print(f"  [{i}] {time_str}  action={action:<7} rule_id={rule_id:<6} guardrails={g_str}")
        
    print(f"\nAudit hash: {short_hash} (verifiable against deployed policy)")


if __name__ == "__main__":
    main()
