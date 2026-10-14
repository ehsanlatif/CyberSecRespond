"""dfir_taskgen — generate a complete Harbor task (post-compromise DFIR subdomain) from a
declarative blueprint. One generic verifier for the whole subdomain; the blueprint is the
only per-range authored input (doc 02 §3.0, doc 03 §4)."""
from pathlib import Path

from . import blueprint as blueprint
from . import emit as emit

__all__ = ["generate", "blueprint", "emit"]


def generate(bp: dict, out_dir, disk=None) -> Path:
    """Emit the full task package for a validated blueprint into out_dir/<range_id>/."""
    out = Path(out_dir) / bp["range_id"]
    out.mkdir(parents=True, exist_ok=True)

    emit.emit_task_toml(bp, out)
    emit.emit_dockerfile(bp, out)
    emit.emit_instruction(bp, out)
    emit.emit_sas(bp, out)
    emit.emit_assets_disk(bp, out, Path(disk) if disk else None)
    emit.emit_verifier(bp, out)
    emit.emit_solution(bp, out)     # Harbor Oracle solver (solution/solve.sh)
    emit.emit_baselines(bp, out)
    return out
