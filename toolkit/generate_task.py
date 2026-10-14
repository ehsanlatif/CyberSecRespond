#!/usr/bin/env python3
"""Generate a complete Harbor task for the post-compromise DFIR subdomain from a blueprint.

The blueprint carries the input dimensions of a range (capability targets, difficulty, the
ATT&CK chain, artifacts, remediation). Everything else — task.toml, Dockerfile,
instruction.md, the SAS feed, the manifest, the verifier bindings, and the three baselines —
is emitted mechanically. The verifier itself is fixed for the whole subdomain and is
parametrized only by the generated manifest.json (doc 02 §3.0).

Usage:
    python generate_task.py BLUEPRINT [--out DIR] [--disk disk.tar.gz]
    python generate_task.py --scaffold RANGE_ID [--os centos --version 7 --difficulty 2]

Examples:
    python generate_task.py blueprints/ssh-miner.json --out tasks/
    python generate_task.py blueprints/ssh-miner.json --disk build/ssh-miner/disk.tar.gz
    python generate_task.py --scaffold rdp-service-abuse --os windows --difficulty 3 > bp.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dfir_taskgen import blueprint as bpmod
from dfir_taskgen import generate


SCAFFOLD = {
    "range_id": "REPLACE-ME",
    "title": "Post-compromise forensic investigation and remediation planning",
    "description": "REPLACE-ME",
    "tags": ["security", "dfir", "incident-response", "long-horizon"],
    "difficulty": 2,
    "platform": {"os": "linux", "version": "1"},
    "no_cve_entry": True,
    "scenario": "REPLACE-ME: one-paragraph scenario shown to the agent.",
    "chain": [
        {"step": 1, "attck": "T1110", "desc": "initial access"},
        {"step": 2, "attck": "T1059.004", "desc": "execution", "depends_on": [1]},
    ],
    "artifacts": [
        {"chk": "CHK-01", "path": "/REPLACE/ME", "kind": "REPLACE",
         "capability": "ENT-P01", "alerted": True, "weight": 1.0, "match": ["REPLACE"]},
        {"chk": "CHK-02", "path": "/REPLACE/ME/silent", "kind": "REPLACE",
         "capability": "PER-I01", "alerted": False, "weight": 2.0},
    ],
    "remediation": [
        {"chk": "CHK-01", "action": "REPLACE", "verify": "REPLACE",
         "phase": "eradicate", "risk_class": "runtime"},
    ],
    "precedence": ["contain", "eradicate", "harden", "rotate", "verify"],
    "decoys": [],
    "judge": {"attribution": True, "quality": True},
}


def _scaffold(args) -> int:
    bp = dict(SCAFFOLD)
    bp["range_id"] = args.scaffold
    bp["platform"] = {"os": args.os, "version": args.version}
    bp["difficulty"] = args.difficulty
    json.dump(bp, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("blueprint", nargs="?", help="path to a blueprint (.json or .yaml)")
    ap.add_argument("--out", default="tasks", help="output directory (default: tasks/)")
    ap.add_argument("--disk", default=None,
                    help="path to the range's disk.tar.gz (from the instance layer)")
    ap.add_argument("--scaffold", metavar="RANGE_ID",
                    help="print a blueprint skeleton for RANGE_ID and exit")
    ap.add_argument("--os", default="linux", help="scaffold: platform os")
    ap.add_argument("--version", default="1", help="scaffold: platform version")
    ap.add_argument("--difficulty", type=int, default=2, help="scaffold: difficulty 1..4")
    args = ap.parse_args(argv)

    if args.scaffold:
        return _scaffold(args)

    if not args.blueprint:
        ap.error("a blueprint path is required (or use --scaffold)")

    try:
        bp = bpmod.load(args.blueprint)
    except bpmod.BlueprintError as exc:
        print(f"blueprint error: {exc}", file=sys.stderr)
        return 2

    out = generate(bp, args.out, disk=args.disk)

    n_files = sum(1 for _ in out.rglob("*") if _.is_file())
    print(f"✓ generated task '{bp['range_id']}' → {out}  ({n_files} files)")
    print(f"  difficulty L{bp['difficulty']} · alert_coverage {bp['alert_coverage']} · "
          f"{len(bp['artifacts'])} artifacts · signature {bpmod_signature(bp)}")
    if not args.disk:
        print("  note: no --disk supplied; see assets/README.md (container build needs "
              "disk.tar.gz).", file=sys.stderr)
    return 0


def bpmod_signature(bp: dict) -> str:
    from dfir_taskgen.emit import _signature
    return _signature(bp)


if __name__ == "__main__":
    raise SystemExit(main())
