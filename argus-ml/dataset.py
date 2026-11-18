"""
Argus EDR — dataset loading and batching.

Loads NDJSON trace files (see schema.py for the format), turns each trace into
a [n_events, N_FEATURES] matrix, and batches variable-length sequences with
padding so they can go through a GRU.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

import torch
from torch.utils.data import Dataset

from schema import LABEL_TO_INT, N_FEATURES, trace_to_matrix


def load_traces(path: str | Path) -> list[dict[str, Any]]:
    """Read an NDJSON file (one trace object per line) into a list of dicts."""
    traces: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            traces.append(json.loads(line))
    return traces


def load_many(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in paths:
        out.extend(load_traces(p))
    return out


class TraceDataset(Dataset):
    """Wraps a list of (matrix, label, technique) samples.

    Can be built two ways:
      * from_traces(...)   — from parsed trace dicts (the real path)
      * from_matrices(...) — from ready-made feature matrices (pipeline tests)
    """

    def __init__(self, samples: list[tuple[torch.Tensor, int, str]]):
        self.samples = samples

    @classmethod
    def from_traces(cls, traces: list[dict[str, Any]]) -> "TraceDataset":
        samples = []
        for tr in traces:
            mat = trace_to_matrix(tr)
            if not mat:
                continue  # skip empty traces
            x = torch.tensor(mat, dtype=torch.float32)
            y = LABEL_TO_INT[tr["label"]]
            technique = tr.get("technique", "")
            samples.append((x, y, technique))
        return cls(samples)

    @classmethod
    def from_matrices(
        cls, matrices: list[list[list[float]]], labels: list[int],
        techniques: list[str] | None = None,
    ) -> "TraceDataset":
        techniques = techniques or [""] * len(matrices)
        samples = [
            (torch.tensor(m, dtype=torch.float32), int(y), t)
            for m, y, t in zip(matrices, labels, techniques)
        ]
        return cls(samples)

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, i: int):
        return self.samples[i]


def collate(batch: list[tuple[torch.Tensor, int, str]]):
    """Pad a batch of variable-length sequences.

    Returns:
        padded   : [B, T_max, N_FEATURES]
        lengths  : [B]  true length of each sequence (for packing / masking)
        labels   : [B]  float {0,1}
        techniques: list[str]
    """
    batch = sorted(batch, key=lambda s: s[0].shape[0], reverse=True)
    seqs, labels, techniques = zip(*batch)
    lengths = torch.tensor([s.shape[0] for s in seqs], dtype=torch.long)
    t_max = int(lengths.max())
    padded = torch.zeros(len(seqs), t_max, N_FEATURES, dtype=torch.float32)
    for i, s in enumerate(seqs):
        padded[i, : s.shape[0]] = s
    return padded, lengths, torch.tensor(labels, dtype=torch.float32), list(techniques)
