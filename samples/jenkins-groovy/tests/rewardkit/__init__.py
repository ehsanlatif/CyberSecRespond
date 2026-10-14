"""rewardkit — the reward substrate the DFIR verifier is written against.

This is a real, self-contained implementation of the (previously fictional) `harbor-rewardkit`
API the criterion files use: the `@criterion` decorator, the `rk.shared.<name>` namespace of
shared helpers, and the `rk.<name>(...)` registrars for parametrized criteria
(`rk.discovered`, `rk.step_verified`, `rk.silent_artifact_recall`). The scoring/aggregation
loop lives in `runner.py`; the Tier-3 judge adapter in `judge.py`.

Design notes:
- `@criterion(shared=True)` registers a helper on `shared` (callable as `rk.shared.<name>`).
- `@criterion(...)` (non-shared) registers a criterion *definition*. A definition with no
  required parameters beyond `workspace` is auto-scheduled to run once; a definition that
  takes extra required parameters (e.g. `discovered(workspace, chk, artifact)`) is a template
  scheduled explicitly via `rk.<name>(...)`.
- `rk.<name>(...)` schedules one instance of criterion `<name>` with bound args + a weight.
- Instance dedup key is (name, positional-args). An explicit registration overrides an
  auto-scheduled one for the same key (this is how `rk.silent_artifact_recall(weight=0.0)`
  turns the auto-scheduled headline metric into a reported-but-unweighted one).
"""
from __future__ import annotations

import inspect


class _Shared:
    """Namespace object populated by @criterion(shared=True); reached as rk.shared.<name>."""


shared = _Shared()

# name -> {"fn", "description", "required_pass", "group"}
_defs: dict = {}
# (name, args_tuple) -> {"name","args","kwargs","weight","auto","group"}
_instances: dict = {}
_current_group = None


def _reset() -> None:
    """Clear all state (the runner calls this before each run)."""
    global _current_group
    _defs.clear()
    _instances.clear()
    for k in [k for k in vars(shared)]:
        delattr(shared, k)
    _current_group = None


def _set_group(group) -> None:
    global _current_group
    _current_group = group


def _required_extra(fn) -> list:
    """Required positional parameters beyond the leading `workspace` (no default, not *args)."""
    params = list(inspect.signature(fn).parameters.values())[1:]
    return [p for p in params
            if p.default is inspect._empty
            and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]


def criterion(_fn=None, *, shared=False, description=None, weight=1.0,
              required_pass=False, **_extra):
    """Register a criterion (or, with shared=True, a shared helper)."""
    def deco(fn):
        if shared:
            setattr(globals()["shared"], fn.__name__, fn)
            return fn
        _defs[fn.__name__] = {
            "fn": fn, "description": description,
            "required_pass": required_pass, "group": _current_group,
        }
        if not _required_extra(fn):          # runnable with only `workspace` → auto-schedule
            _schedule(fn.__name__, (), {}, weight, auto=True)
        return fn
    return deco(_fn) if _fn is not None else deco


def _schedule(name, args, kwargs, weight, auto) -> None:
    key = (name, tuple(args))
    existing = _instances.get(key)
    if existing is not None and not existing["auto"] and auto:
        return                               # never let an auto instance clobber an explicit one
    _instances[key] = {
        "name": name, "args": tuple(args), "kwargs": dict(kwargs),
        "weight": weight, "auto": auto, "group": _current_group,
    }


def __getattr__(name):
    """Any unknown attribute is a registrar: rk.discovered(...), rk.step_verified(...), etc."""
    def register(*args, weight=1.0, **kwargs):
        _schedule(name, args, kwargs, weight, auto=False)
    return register
