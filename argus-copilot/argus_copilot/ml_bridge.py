"""
Bridge to the argus-ml GRU injection detector — an optional second opinion.

The Copilot can consult the learned model from the sibling `argus-ml` project
as one of its tools. Everything here is defensive: if argus-ml, torch, or a
trained `model.pt` is missing, every entry point returns an "unavailable"
result with the reason, and the agent carries on with the rule-based tools.

Feature extraction is NOT re-implemented here: events go through argus-ml's
own `schema.trace_to_matrix`, so the model always sees exactly the features it
was trained on.

Configuration (environment):
    ARGUS_ML_DIR    path to the argus-ml checkout   (default: ../argus-ml next to this repo)
    ARGUS_MODEL_PT  path to the trained checkpoint  (default: <ARGUS_ML_DIR>/model.pt)
    ARGUS_ML_THRESHOLD  decision threshold          (default: 0.5)
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from pathlib import Path
from typing import Any, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
_cache: dict[str, Any] = {}


def _ml_dir() -> Optional[Path]:
    env = os.environ.get("ARGUS_ML_DIR")
    candidates = [Path(env)] if env else [_REPO_ROOT.parent / "argus-ml"]
    for c in candidates:
        if (c / "schema.py").is_file() and (c / "model.py").is_file():
            return c.resolve()
    return None


def _model_path(ml_dir: Optional[Path]) -> Optional[Path]:
    env = os.environ.get("ARGUS_MODEL_PT")
    if env:
        return Path(env)
    return (ml_dir / "model.pt") if ml_dir else None


def _threshold() -> float:
    try:
        return float(os.environ.get("ARGUS_ML_THRESHOLD", "0.5"))
    except ValueError:
        return 0.5


def status() -> dict[str, Any]:
    """Can the learned detector run right now? (Cheap — no model load.)"""
    ml_dir = _ml_dir()
    model_path = _model_path(ml_dir)
    info: dict[str, Any] = {"available": False,
                            "argus_ml_dir": str(ml_dir) if ml_dir else None,
                            "model_path": str(model_path) if model_path else None}
    if ml_dir is None:
        info["reason"] = "argus-ml not found (set ARGUS_ML_DIR)"
    elif model_path is None or not model_path.is_file():
        info["reason"] = "no trained model.pt (train with argus-ml or set ARGUS_MODEL_PT)"
    elif importlib.util.find_spec("torch") is None:
        info["reason"] = "torch is not installed"
    else:
        info["available"] = True
        info["reason"] = "ok"
    return info


def _load():
    """Load argus-ml's schema + model and the checkpoint (cached)."""
    key = f"{os.environ.get('ARGUS_ML_DIR')}|{os.environ.get('ARGUS_MODEL_PT')}"
    if _cache.get("key") == key:
        return _cache["schema"], _cache["model"]

    ml_dir = _ml_dir()
    model_path = _model_path(ml_dir)
    import torch  # noqa: WPS433 — optional dependency

    if str(ml_dir) not in sys.path:
        sys.path.insert(0, str(ml_dir))
    schema = importlib.import_module("schema")
    model_mod = importlib.import_module("model")

    ckpt = torch.load(str(model_path), map_location="cpu")
    saved_names = ckpt.get("feature_names")
    if saved_names and list(saved_names) != list(schema.FEATURE_NAMES):
        raise ValueError("model.pt was trained on a different feature layout "
                         "than the current argus-ml schema.py")
    model = model_mod.InjectionGRU(hidden_size=int(ckpt.get("hidden_size", 48)))
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    _cache.update(key=key, schema=schema, model=model)
    return schema, model


def score_trace(proc: Any) -> dict[str, Any]:
    """Score one ProcessTrace. Never raises — failures come back as data."""
    st = status()
    if not st["available"]:
        return {"available": False, "reason": st["reason"]}
    if not getattr(proc, "events", None):
        return {"available": True, "scored": False,
                "reason": "no hook events for this process — nothing to score"}
    try:
        import torch
        schema, model = _load()
        matrix = schema.trace_to_matrix({"events": proc.events})
        x = torch.tensor([matrix], dtype=torch.float32)
        lengths = torch.tensor([len(matrix)])
        p = float(model.predict_proba(x, lengths)[0])
    except Exception as e:  # model/feature mismatch, corrupt checkpoint, ...
        return {"available": False, "reason": f"model error: {e}"}
    thr = _threshold()
    out = {
        "available": True, "scored": True,
        "probability": round(p, 4),
        "label": "injection" if p >= thr else "benign",
        "threshold": thr,
        "n_events": len(matrix),
        "note": "Learned second opinion; trained on a small lab dataset.",
    }
    # A model that uses inter-event timing is unreliable on the agent log,
    # which carries no timestamps (see argus-ml RESULTS §6).
    if "log_dt_ms" in getattr(schema, "FEATURE_NAMES", []) and \
            not any("t_ms" in e for e in proc.events):
        out["caveat"] = ("this model uses event timing but the events have no "
                         "timestamps; its score is unreliable here")
    return out
