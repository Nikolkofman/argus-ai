"""
Argus EDR — evaluation.

Two things:

1. metrics(model, dataset) — detection rate, false-positive rate, precision,
   AUC, and a per-technique detection breakdown.

2. leave_one_technique_out(traces) — the generalisation test that matters for a
   detector: for each injection technique, train on every OTHER technique (plus
   all benign traces) and test detection on the held-out technique. A model that
   only memorised the training techniques scores poorly here; one that learned
   the shape of injection generalises.
"""

from __future__ import annotations

import argparse
import glob

import torch
from torch.utils.data import DataLoader

from dataset import TraceDataset, collate, load_many
from model import InjectionGRU
from schema import LABEL_INJECTION, LABEL_TO_INT


def _predict_all(model: InjectionGRU, ds: TraceDataset):
    loader = DataLoader(ds, batch_size=64, shuffle=False, collate_fn=collate)
    probs, labels, techs = [], [], []
    model.eval()
    with torch.no_grad():
        for padded, lengths, y, t in loader:
            probs.append(torch.sigmoid(model(padded, lengths)))
            labels.append(y)
            techs.extend(t)
    return torch.cat(probs), torch.cat(labels), techs


def _auc(probs: torch.Tensor, labels: torch.Tensor) -> float:
    """ROC AUC without sklearn (rank-based / Mann–Whitney)."""
    pos = probs[labels == 1]
    neg = probs[labels == 0]
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    order = torch.argsort(probs)
    ranks = torch.empty_like(order, dtype=torch.float32)
    ranks[order] = torch.arange(1, len(probs) + 1, dtype=torch.float32)
    sum_pos = ranks[labels == 1].sum()
    n_pos, n_neg = len(pos), len(neg)
    return float((sum_pos - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def metrics(model: InjectionGRU, ds: TraceDataset, threshold: float = 0.5) -> dict:
    probs, labels, techs = _predict_all(model, ds)
    pred = (probs >= threshold).float()
    tp = int(((pred == 1) & (labels == 1)).sum())
    fp = int(((pred == 1) & (labels == 0)).sum())
    tn = int(((pred == 0) & (labels == 0)).sum())
    fn = int(((pred == 0) & (labels == 1)).sum())

    # per-technique detection (only injection samples carry a technique)
    per_tech: dict[str, list[int]] = {}
    for p, y, t in zip(pred.tolist(), labels.tolist(), techs):
        if y == 1 and t:
            hit, total = per_tech.get(t, [0, 0])
            per_tech[t] = [hit + int(p == 1), total + 1]
    per_tech_rate = {t: round(h / n, 3) for t, (h, n) in per_tech.items()}

    return {
        "n": len(labels),
        "detection_rate": round(tp / (tp + fn), 3) if (tp + fn) else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 3) if (fp + tn) else 0.0,
        "precision": round(tp / (tp + fp), 3) if (tp + fp) else 0.0,
        "auc": round(_auc(probs, labels), 3),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "per_technique_detection": per_tech_rate,
    }


def leave_one_technique_out(traces: list[dict], epochs: int = 40, **train_kw) -> dict:
    """Train holding out each injection technique in turn; report held-out
    detection rate. Imported lazily to avoid a circular import at module load."""
    from train import train as train_model

    benign = [t for t in traces if t["label"] != LABEL_INJECTION]
    injection = [t for t in traces if t["label"] == LABEL_INJECTION]
    techniques = sorted({t.get("technique", "") for t in injection if t.get("technique")})

    results: dict[str, dict] = {}
    for held in techniques:
        train_traces = benign + [t for t in injection if t.get("technique") != held]
        test_traces = [t for t in injection if t.get("technique") == held]
        if not test_traces:
            continue
        model, _ = train_model(
            TraceDataset.from_traces(train_traces), epochs=epochs, verbose=False, **train_kw
        )
        test_ds = TraceDataset.from_traces(test_traces)
        probs, labels, _ = _predict_all(model, test_ds)
        detected = int((probs >= 0.5).sum())
        results[held] = {
            "held_out_samples": len(test_traces),
            "detected": detected,
            "detection_rate": round(detected / len(test_traces), 3),
        }
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", nargs="+", required=True)
    ap.add_argument("--model", required=True)
    args = ap.parse_args()

    paths: list[str] = []
    for pat in args.data:
        paths.extend(glob.glob(pat))
    traces = load_many(paths)
    ds = TraceDataset.from_traces(traces)

    ckpt = torch.load(args.model, weights_only=False)
    model = InjectionGRU(hidden_size=ckpt.get("hidden_size", 48))
    model.load_state_dict(ckpt["state_dict"])

    import json
    print(json.dumps(metrics(model, ds), indent=2))


if __name__ == "__main__":
    main()
