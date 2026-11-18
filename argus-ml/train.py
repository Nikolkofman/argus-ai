"""
Argus EDR — training loop.

Usage:
    python train.py --data data/*.ndjson --epochs 40 --out model.pt

Loads NDJSON traces, splits into train/val, trains the GRU, prints per-epoch
metrics, and saves the best model (by validation AUC) to --out.
"""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, random_split

from dataset import TraceDataset, collate, load_many
from model import InjectionGRU
from schema import FEATURE_NAMES


def evaluate_loader(model: InjectionGRU, loader: DataLoader) -> dict:
    """Return loss and simple detection metrics over a loader."""
    model.eval()
    bce = nn.BCEWithLogitsLoss()
    total_loss, n = 0.0, 0
    tp = fp = tn = fn = 0
    with torch.no_grad():
        for padded, lengths, labels, _ in loader:
            logits = model(padded, lengths)
            total_loss += bce(logits, labels).item() * len(labels)
            n += len(labels)
            pred = (torch.sigmoid(logits) >= 0.5).float()
            tp += int(((pred == 1) & (labels == 1)).sum())
            fp += int(((pred == 1) & (labels == 0)).sum())
            tn += int(((pred == 0) & (labels == 0)).sum())
            fn += int(((pred == 0) & (labels == 1)).sum())
    detection = tp / (tp + fn) if (tp + fn) else 0.0   # recall on injection
    fpr = fp / (fp + tn) if (fp + tn) else 0.0          # false positives on benign
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    return {
        "loss": total_loss / max(n, 1),
        "detection_rate": detection,
        "false_positive_rate": fpr,
        "precision": precision,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def train(
    dataset: TraceDataset,
    epochs: int = 40,
    batch_size: int = 32,
    lr: float = 1e-3,
    val_frac: float = 0.25,
    hidden_size: int = 48,
    seed: int = 0,
    verbose: bool = True,
) -> tuple[InjectionGRU, dict]:
    torch.manual_seed(seed)
    n_val = max(1, int(len(dataset) * val_frac))
    n_train = len(dataset) - n_val
    train_ds, val_ds = random_split(
        dataset, [n_train, n_val], generator=torch.Generator().manual_seed(seed)
    )
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, collate_fn=collate)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False, collate_fn=collate)

    model = InjectionGRU(hidden_size=hidden_size)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    bce = nn.BCEWithLogitsLoss()

    best_score, best_loss, best_state, best_metrics = -1.0, float("inf"), None, {}
    for epoch in range(1, epochs + 1):
        model.train()
        for padded, lengths, labels, _ in train_loader:
            opt.zero_grad()
            loss = bce(model(padded, lengths), labels)
            loss.backward()
            opt.step()

        m = evaluate_loader(model, val_loader)
        # select on detection rate penalised by FPR; tie-break on lower val loss
        score = m["detection_rate"] - 0.5 * m["false_positive_rate"]
        better = score > best_score + 1e-9 or (
            abs(score - best_score) <= 1e-9 and m["loss"] < best_loss
        )
        if better:
            best_score, best_loss = score, m["loss"]
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            best_metrics = m
        if verbose and (epoch % 5 == 0 or epoch == 1):
            print(f"epoch {epoch:3d} | val loss {m['loss']:.3f} | "
                  f"detect {m['detection_rate']:.2f} | FPR {m['false_positive_rate']:.2f} | "
                  f"prec {m['precision']:.2f}")

    if best_state is not None:
        model.load_state_dict(best_state)
    return model, best_metrics


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", nargs="+", required=True, help="NDJSON file(s) or globs")
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--hidden-size", type=int, default=48)
    ap.add_argument("--out", default="model.pt")
    args = ap.parse_args()

    paths: list[str] = []
    for pat in args.data:
        paths.extend(glob.glob(pat))
    if not paths:
        raise SystemExit(f"no files matched: {args.data}")
    traces = load_many(paths)
    print(f"loaded {len(traces)} traces from {len(paths)} file(s)")
    ds = TraceDataset.from_traces(traces)

    model, metrics = train(ds, epochs=args.epochs, batch_size=args.batch_size,
                           hidden_size=args.hidden_size)
    torch.save(
        {"state_dict": model.state_dict(),
         "hidden_size": args.hidden_size,
         "feature_names": FEATURE_NAMES},
        args.out,
    )
    print("best val metrics:", json.dumps(metrics, indent=2))
    print(f"saved model → {args.out}")


if __name__ == "__main__":
    main()
