"""
Mechanical pipeline self-test — NOT a model evaluation and NOT attack data.

It fabricates abstract random feature matrices with a planted, learnable signal
in a couple of feature dimensions, purely to confirm that dataset batching,
the GRU forward/backward pass, the training loop, and the metrics all run and
converge on something trivially separable. Real evaluation happens on real
traces captured on Windows.
"""

from __future__ import annotations

import random

import torch

from dataset import TraceDataset
from evaluate import metrics
from schema import N_FEATURES
from train import train


def _make_matrix(rng: random.Random, positive: bool) -> list[list[float]]:
    n = rng.randint(4, 20)
    rows = []
    for _ in range(n):
        row = [rng.random() for _ in range(N_FEATURES)]
        if positive:
            # plant signal: lift two dims so class 1 is separable
            row[6] = min(1.0, row[6] + 0.6)   # "cross_process" slot
            row[7] = min(1.0, row[7] + 0.6)   # "exec_protect" slot
        rows.append(row)
    return rows


def main():
    rng = random.Random(0)
    mats, labels = [], []
    for _ in range(120):
        pos = rng.random() < 0.5
        mats.append(_make_matrix(rng, pos))
        labels.append(1 if pos else 0)

    ds = TraceDataset.from_matrices(mats, labels)
    print(f"[smoke] dataset size: {len(ds)}, feature dim: {N_FEATURES}")

    torch.manual_seed(0)
    model, val_metrics = train(ds, epochs=25, verbose=True)
    print("[smoke] val metrics:", val_metrics)

    full = metrics(model, ds)
    print("[smoke] full-set metrics:", full)

    ok = full["detection_rate"] > 0.9 and full["false_positive_rate"] < 0.1
    print("[smoke] PIPELINE OK" if ok else "[smoke] pipeline ran but did not converge")


if __name__ == "__main__":
    main()
