"""Convert a bounded LANL auth.txt(.gz) selection to CyberSentinel NDJSON."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.lanl_auth import iter_auth_events  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="LANL auth.txt or auth.txt.gz")
    parser.add_argument("output", type=Path, help="Output .jsonl/.ndjson file")
    parser.add_argument("--limit", type=int, default=500, help="Maximum output records (default: 500)")
    parser.add_argument("--sample-every", type=int, default=1, help="Keep one row every N rows")
    parser.add_argument("--time-start", type=int, help="Minimum LANL elapsed-seconds value")
    parser.add_argument("--time-end", type=int, help="Maximum LANL elapsed-seconds value")
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be at least 1")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with args.output.open("w", encoding="utf-8", newline="\n") as out:
        for event in iter_auth_events(args.input, limit=args.limit, sample_every=args.sample_every, time_start=args.time_start, time_end=args.time_end):
            out.write(json.dumps(event, ensure_ascii=False) + "\n")
            count += 1
    print(f"Wrote {count} LANL authentication events to {args.output}")


if __name__ == "__main__":
    main()
