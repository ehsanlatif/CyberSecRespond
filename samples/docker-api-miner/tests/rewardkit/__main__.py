"""CLI: `python -m rewardkit --tests DIR [--app DIR --disk DIR --sas DIR]`.

Invoked by tests/test.sh inside the Harbor container. Scores /app against the range's
manifest and writes reward.json (+ reward-details.json), then prints reward.json to stdout.
"""
from __future__ import annotations

import argparse
import json
import sys

from rewardkit.runner import run


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="rewardkit", description=__doc__)
    ap.add_argument("--tests", default="/tests", help="tests directory (manifest + criteria)")
    ap.add_argument("--app", default="/app", help="agent workspace (the reports to score)")
    ap.add_argument("--disk", default="/disk", help="forensic-image evidence root")
    ap.add_argument("--sas", default="/sas", help="security-product feed evidence root")
    args = ap.parse_args(argv)

    reward = run(args.tests, args.app, args.disk, args.sas)
    json.dump(reward, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
