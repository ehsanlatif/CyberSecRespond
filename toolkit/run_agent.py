#!/usr/bin/env python3
"""Run a Gemini agent on a generated DFIR task, then score it (Opus judge by default).

The agent investigates the range inside a network-isolated, read-only Docker sandbox
(/disk + /sas mounted ro, --network none), driving a shell tool over many turns, and writes
the five reports via a write_report tool. Then rewardkit scores /app against the manifest.

  export GEMINI_API_KEY=...        # the policy (agent)
  export ANTHROPIC_API_KEY=...     # the judge
  python3 run_agent.py tasks/ssh-miner                       # Gemini agent, Opus judge
  python3 run_agent.py tasks/ssh-miner --judge none          # skip the LLM judge (Tier 1+2 only)
  python3 run_agent.py tasks/ssh-miner --local               # no Docker (host subprocess, read-only)

Family separation (doc 02 sec 3.5): Gemini policy + Anthropic Opus judge, by default.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
REPORTS = ("progress.md", "intrusion-report.md", "vuln-report.md",
           "baseline-report.md", "remediation-plan.md")
SANDBOX_IMG = "ubuntu:24.04"
LOCAL_ALLOW = {"ls", "cat", "head", "tail", "grep", "egrep", "fgrep", "find", "stat", "wc",
               "sort", "uniq", "cut", "awk", "sed", "tr", "file", "strings", "od", "xxd",
               "basename", "dirname", "echo", "pwd", "test", "tree", "tac", "nl", "realpath"}


# ------------------------------------------------------------------ sandbox (docker | local)

class Sandbox:
    def __init__(self, disk: Path, sas: Path, use_docker: bool):
        self.use_docker = use_docker
        self.cid = None
        if use_docker:
            self.cid = subprocess.check_output([
                "docker", "run", "-d", "--rm", "--network", "none",
                "-v", f"{disk.resolve()}:/disk:ro", "-v", f"{sas.resolve()}:/sas:ro",
                SANDBOX_IMG, "sleep", "3600",
            ], text=True).strip()
        else:
            self.root = Path(tempfile.mkdtemp(prefix="sbox_"))
            (self.root / "disk").symlink_to(disk.resolve())
            (self.root / "sas").symlink_to(sas.resolve())

    def shell(self, command: str) -> str:
        try:
            if self.use_docker:
                out = subprocess.run(["docker", "exec", self.cid, "sh", "-c", command],
                                     capture_output=True, text=True, timeout=30)
            else:
                first = (shlex.split(command) or [""])[0].split("/")[-1]
                if first not in LOCAL_ALLOW:
                    return f"[blocked in --local mode: '{first}' not in the read-only allowlist]"
                out = subprocess.run(["sh", "-c", command], cwd=self.root,
                                     capture_output=True, text=True, timeout=30)
            body = (out.stdout or "") + (("\n[stderr] " + out.stderr) if out.stderr else "")
            return body[:4000] if body.strip() else "[no output]"
        except subprocess.TimeoutExpired:
            return "[command timed out after 30s]"
        except Exception as e:
            return f"[shell error: {type(e).__name__}: {e}]"

    def close(self):
        if self.use_docker and self.cid:
            subprocess.run(["docker", "rm", "-f", self.cid], capture_output=True)
        elif not self.use_docker:
            shutil.rmtree(self.root, ignore_errors=True)


# ------------------------------------------------------------------ Gemini agent loop

TOOLS = [{"functionDeclarations": [
    {"name": "shell",
     "description": "Run ONE read-only shell command inside the analysis sandbox to inspect "
                    "the forensic image at /disk and the security feed at /sas. Use ls, cat, "
                    "grep -r, find, head, etc. The disk is read-only.",
     "parameters": {"type": "OBJECT",
                    "properties": {"command": {"type": "STRING"}}, "required": ["command"]}},
    {"name": "write_report",
     "description": "Write ONE of the five required report files. Call once per file. "
                    "Every finding must carry a backtick citation like `/disk/path` or "
                    "`/sas/alerts.json`.",
     "parameters": {"type": "OBJECT",
                    "properties": {"filename": {"type": "STRING",
                                                "enum": list(REPORTS)},
                                   "content": {"type": "STRING"}},
                    "required": ["filename", "content"]}},
]}]


def gemini(model, key, contents, system):
    body = {"contents": contents, "tools": TOOLS,
            "systemInstruction": {"parts": [{"text": system}]},
            "generationConfig": {"temperature": 0.2}}
    req = urllib.request.Request(GEMINI_URL.format(model=model),
                                 data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json",
                                          "x-goog-api-key": key})
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.loads(resp.read())


def run_agent(task: Path, model: str, max_turns: int, use_docker: bool, app: Path) -> None:
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key:
        sys.exit("set GEMINI_API_KEY (the policy/agent)")
    disk = task / "assets" / "disk"
    sas = task / "environment" / "sas-mock"       # SAS feed lives under environment/ (build context)
    if not disk.exists():
        sys.exit(f"no generated disk at {disk} — run: python3 build_disk.py {task}")
    instruction = (task / "instruction.md").read_text()
    system = (instruction + "\n\nYou operate AUTONOMOUSLY: no human is watching, so never ask "
              "questions — investigate with the shell tool and act. Explore beyond the alerts: "
              "many findings are silent (not in /sas). Produce ALL FIVE files with write_report; "
              "every finding needs a backtick path citation under /disk or /sas.")

    sb = Sandbox(disk, sas, use_docker)
    contents = [{"role": "user",
                 "content": None}]  # placeholder, replaced below
    contents = [{"role": "user", "parts": [{"text": "Begin the investigation now."}]}]
    written = set()
    try:
        for turn in range(1, max_turns + 1):
            try:
                resp = gemini(model, key, contents, system)
            except Exception as e:
                print(f"[turn {turn}] gemini error: {e}", file=sys.stderr)
                break
            cand = (resp.get("candidates") or [{}])[0]
            parts = cand.get("content", {}).get("parts", []) or []
            contents.append({"role": "model", "parts": parts})
            calls = [p["functionCall"] for p in parts if "functionCall" in p]
            texts = [p["text"] for p in parts if "text" in p]
            if texts:
                print(f"[turn {turn}] " + " ".join(texts)[:160])
            if not calls:
                break  # model produced no tool call -> considers itself done
            responses = []
            for c in calls:
                name, a = c["name"], c.get("args", {}) or {}
                if name == "shell":
                    out = sb.shell(a.get("command", ""))
                    print(f"[turn {turn}] shell: {a.get('command','')[:80]}")
                    responses.append({"functionResponse": {"name": name,
                                     "response": {"output": out}}})
                elif name == "write_report":
                    fn = a.get("filename", "")
                    if fn in REPORTS:
                        (app / fn).write_text(a.get("content", ""))
                        written.add(fn)
                        print(f"[turn {turn}] wrote {fn} ({len(written)}/5)")
                    responses.append({"functionResponse": {"name": name,
                                     "response": {"status": "ok", "written": sorted(written)}}})
            missing = [r for r in REPORTS if r not in written]
            nudge = ("" if not missing else
                     f"\nStill missing reports: {missing}. Keep investigating and write them.")
            responses.append({"functionResponse": {"name": "shell",
                             "response": {"output": f"[progress] {len(written)}/5 written.{nudge}"}}}
                             ) if missing and not calls else None
            contents.append({"role": "user", "parts": [r for r in responses if r]})
            if len(written) >= 5:
                print(f"[turn {turn}] all 5 reports written; finishing.")
                break
    finally:
        sb.close()
    for r in REPORTS:                       # ensure files exist so structure gate is meaningful
        (app / r).touch(exist_ok=True)
    print(f"reports written: {sorted(written)}")


# ------------------------------------------------------------------ main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("task")
    ap.add_argument("--model", default="gemini-2.5-flash", help="Gemini policy model")
    ap.add_argument("--judge", default="anthropic/claude-opus-5",
                    help="scoring judge (provider/model), or 'none' for Tier 1+2 only")
    ap.add_argument("--max-turns", type=int, default=40)
    ap.add_argument("--local", action="store_true", help="no Docker; host subprocess (read-only allowlist)")
    args = ap.parse_args(argv)

    task = Path(args.task)
    use_docker = not args.local
    if use_docker and subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        print("[docker unavailable -> falling back to --local]", file=sys.stderr)
        use_docker = False

    app = Path(tempfile.mkdtemp(prefix="app_"))
    t0 = time.time()
    print(f"== agent: {args.model} on {task.name}  (sandbox: {'docker' if use_docker else 'local'}) ==")
    run_agent(task, args.model, args.max_turns, use_docker, app)

    # score
    if args.judge and args.judge != "none":
        os.environ["REWARDKIT_JUDGE"] = args.judge
    else:
        os.environ.pop("REWARDKIT_JUDGE", None)
    from rewardkit.runner import run
    reward = run(task / "tests", app, task / "assets" / "disk", task / "environment" / "sas-mock")
    print(f"\n== reward.json ({time.time()-t0:.0f}s, judge={args.judge}) ==")
    print(json.dumps(reward, indent=2))
    print(f"\nreports + reward-details.json in: {app}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
