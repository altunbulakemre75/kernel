"""kyvern-anchor — timestamp the head of the audit chain with an RFC 3161 TSA.

Run it on a schedule (cron, Windows Task Scheduler, systemd timer). It never
touches the decision path: it only reads the chain and appends a receipt to
<chain stem>.anchors.jsonl.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from services.decision.anchors import AnchorError, anchor_head
from services.decision.chain_writer import AuditWriteError, last_entry
from services.decision.rfc3161_anchor import DEFAULT_TSA_URL, RFC3161Anchor, load_roots
from shared.paths import default_chain_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kyvern-anchor",
        description="Timestamp the head of a Kyvern audit chain with an RFC 3161 Time Stamping Authority.",
    )
    parser.add_argument(
        "chain_file", nargs="?", default=None,
        help="audit chain JSONL (default: $KYVERN_CHAIN_PATH, else ~/.kyvern/chain.jsonl)",
    )
    parser.add_argument("--tsa-url", default=DEFAULT_TSA_URL, help=f"TSA endpoint (default: {DEFAULT_TSA_URL})")
    parser.add_argument(
        "--tsa-root", action="append", default=None,
        help="PEM file with trusted TSA root certificate(s); repeatable (default: certifi bundle)",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds to wait for the TSA")
    args = parser.parse_args(argv)

    chain_path = Path(args.chain_file) if args.chain_file else default_chain_path()
    try:
        head = last_entry(chain_path)
        if head is None:
            print(f"Nothing to anchor: {chain_path} is empty")
            return 0
        anchor = RFC3161Anchor(args.tsa_url, roots=load_roots(args.tsa_root), timeout_s=args.timeout)
        receipt = anchor_head(chain_path, anchor)
    except (AnchorError, AuditWriteError, OSError, ValueError) as exc:
        print(f"Anchoring failed: {exc}", file=sys.stderr)
        return 1

    if receipt is None:
        print(f"Chain head {head['chain_index']} is already anchored")
    else:
        print(
            f"Anchored chain_index {receipt['chain_index']} at {receipt['anchored_at']} "
            f"via {receipt['tsa_url']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
