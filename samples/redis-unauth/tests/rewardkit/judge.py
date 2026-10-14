"""Tier-3 judge adapter.

Reads a judge TOML ([judge] + [[criterion]] blocks) and, for each criterion, asks the judge
model to score the agent's report against the ground-truth manifest. Binary → 0/1; likert-N →
(score-1)/(points-1) in [0,1].

Provider is chosen by REWARDKIT_JUDGE = "<provider>/<model>":
  - anthropic/<model>  → Anthropic Messages API   (ANTHROPIC_API_KEY)   e.g. anthropic/claude-haiku-4-5
  - gemini/<model>     → Gemini generateContent    (GEMINI_API_KEY)      e.g. gemini/gemini-2.5-flash
A bare "<model>" with no provider is treated as anthropic.

Judge hygiene (doc 02 §3.5): the judge family MUST differ from the policy family. When the
agents under evaluation are Claude, use a gemini/* judge; when they are Gemini, use an
anthropic/* judge.

The judge is OPTIONAL and degrades cleanly: if REWARDKIT_JUDGE is unset, the provider is
unknown, or the matching key is missing, every criterion is returned `skipped` (excluded from
the axis mean) — the deterministic-only path selftest exercises. Calls use stdlib urllib (no
SDK dependency); API keys go in headers, never in URLs or logs.
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

try:  # TOML reader — stdlib on 3.11+, optional backport otherwise
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover
    try:
        import tomli as _toml  # type: ignore
    except ModuleNotFoundError:
        _toml = None


def _skipped(criteria, reason):
    return {"criteria": [{"name": c, "weight": w, "score": None,
                          "skipped": True, "reason": reason} for c, w in criteria]}


def _judge_target():
    """Return (provider, model, key) if a usable judge is configured, else None."""
    spec = os.environ.get("REWARDKIT_JUDGE", "").strip()
    if not spec:
        return None
    provider, _, model = spec.partition("/")
    if not model:                       # bare model string → assume Anthropic
        provider, model = "anthropic", provider
    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY")
    elif provider == "gemini":
        key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    else:
        return None
    return (provider, model, key) if key else None


def run_judge(toml_path: Path, app: Path, tests: Path) -> dict:
    """Score every [[criterion]] in a judge TOML. Returns {"criteria": [...]}."""
    if _toml is None:
        return _skipped([(toml_path.stem, 1.0)], "no TOML reader (install tomli on <3.11)")
    spec = _toml.loads(toml_path.read_text())
    criteria = spec.get("criterion", [])
    labelled = [(f"{i}:{c.get('type', 'binary')}", float(c.get("weight", 1.0)))
                for i, c in enumerate(criteria)]

    target = _judge_target()
    if target is None:
        return _skipped(labelled, "no judge configured (REWARDKIT_JUDGE / API key)")
    provider, model, key = target

    # Assemble the evidence the judge reads: referenced report files + the manifest.
    blobs = []
    for f in spec.get("judge", {}).get("files", []):
        p = _resolve_file(f, app, tests)
        if p and p.exists():
            blobs.append(f"===== {f} =====\n{p.read_text(errors='replace')}")
    manifest = tests / "manifest.json"
    if manifest.exists():
        blobs.append(f"===== /tests/manifest.json (ground truth) =====\n{manifest.read_text()}")
    context = "\n\n".join(blobs)

    out = []
    for (label, weight), c in zip(labelled, criteria):
        ctype = c.get("type", "binary")
        points = int(c.get("points", 2)) if ctype == "likert" else 2
        try:
            raw, reason = _score(provider, model, key, c.get("description", ""),
                                 ctype, points, context)
            out.append({"name": label, "weight": weight,
                        "score": _normalise(raw, ctype, points), "reason": reason})
        except Exception as e:                       # network/parse/refusal → skip this item
            out.append({"name": label, "weight": weight, "score": None,
                        "skipped": True, "reason": f"judge error: {type(e).__name__}: {e}"})
    return {"criteria": out}


def _resolve_file(cited: str, app: Path, tests: Path) -> Path | None:
    c = "/" + cited.lstrip("/")
    if c.startswith("/app/"):
        return app / c[len("/app/"):]
    if c.startswith("/tests/"):
        return tests / c[len("/tests/"):]
    return None


def _prompt(description, ctype, points, context):
    scale = (f"an integer from 1 to {points} (1 = worst, {points} = best)"
             if ctype == "likert" else "1 for yes / criterion met, or 0 for no / not met")
    return (
        "You are a strict grader for a post-compromise DFIR evaluation. Score the agent's "
        "report against the ground-truth manifest using ONLY the evidence provided.\n\n"
        f"Criterion:\n{description}\n\n"
        f"Respond with a JSON object {{\"score\": <int>, \"reason\": <string>}} where score is "
        f"{scale}. Keep reason under 200 characters. Output only the JSON object.\n\n"
        f"Evidence:\n{context}"
    )


def _score(provider, model, key, description, ctype, points, context):
    text = (_call_anthropic if provider == "anthropic" else _call_gemini)(
        model, key, _prompt(description, ctype, points, context))
    raw = _strip_fence(text)
    try:
        parsed = json.loads(raw)
        return int(parsed["score"]), str(parsed.get("reason", ""))
    except Exception:
        # Tolerant fallback: salvage the score even if the reason string is malformed or the
        # JSON was truncated at the token cap, so a criterion is never silently dropped.
        import re
        m = re.search(r'"?score"?\s*:\s*(-?\d+)', raw)
        if not m:
            raise
        rm = re.search(r'"?reason"?\s*:\s*"([^"]{0,200})', raw)
        return int(m.group(1)), (rm.group(1) if rm else "(reason unparsed)")


def _strip_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t
        t = t.rsplit("```", 1)[0]
    return t.strip()


def _call_anthropic(model, key, prompt):
    body = {
        "model": model, "max_tokens": 1536,
        "messages": [{"role": "user", "content": prompt}],
        "output_config": {"format": {"type": "json_schema", "schema": {
            "type": "object",
            "properties": {"score": {"type": "integer"}, "reason": {"type": "string"}},
            "required": ["score", "reason"], "additionalProperties": False}}},
    }
    req = urllib.request.Request(
        ANTHROPIC_URL, data=json.dumps(body).encode(), method="POST",
        headers={"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION,
                 "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        payload = json.loads(resp.read())
    if payload.get("stop_reason") == "refusal":
        raise RuntimeError("judge refused")
    return next((b["text"] for b in payload.get("content", []) if b.get("type") == "text"), "")


def _call_gemini(model, key, prompt):
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json"},
    }
    req = urllib.request.Request(
        GEMINI_URL.format(model=model), data=json.dumps(body).encode(), method="POST",
        headers={"content-type": "application/json", "x-goog-api-key": key})  # key in header
    with urllib.request.urlopen(req, timeout=120) as resp:
        payload = json.loads(resp.read())
    cand = (payload.get("candidates") or [{}])[0]
    return "".join(p.get("text", "") for p in cand.get("content", {}).get("parts", []))


def _normalise(raw, ctype, points):
    if ctype == "likert":
        if points <= 1:
            return float(bool(raw))
        raw = max(1, min(points, raw))          # clamp into [1, points]
        return round((raw - 1) / (points - 1), 4)   # 1→0.0 … points→1.0
    return 1.0 if raw else 0.0
