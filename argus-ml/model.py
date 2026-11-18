"""
Argus EDR — injection-detection model.

A small GRU over the event sequence. Each event's feature vector is projected,
the GRU reads the sequence, and the last *valid* hidden state (accounting for
padding) feeds a linear layer that outputs a single logit: the probability that
this process was the victim of an injection.

Deliberately small — the dataset is modest, so a large model would just
memorise it. Keep hidden_size in the 32–64 range.
"""

from __future__ import annotations

import torch
import torch.nn as nn

from schema import N_FEATURES


class InjectionGRU(nn.Module):
    def __init__(
        self,
        n_features: int = N_FEATURES,
        hidden_size: int = 48,
        num_layers: int = 1,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.input_proj = nn.Linear(n_features, hidden_size)
        self.gru = nn.GRU(
            input_size=hidden_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.head = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(hidden_size, 1),
        )

    def forward(self, padded: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        """padded: [B, T, F], lengths: [B] → logits: [B]."""
        x = torch.relu(self.input_proj(padded))
        packed = nn.utils.rnn.pack_padded_sequence(
            x, lengths.cpu(), batch_first=True, enforce_sorted=False
        )
        _, h_n = self.gru(packed)          # h_n: [num_layers, B, H]
        last = h_n[-1]                     # [B, H] — final layer's hidden state
        return self.head(last).squeeze(-1) # [B]

    @torch.no_grad()
    def predict_proba(self, padded: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        self.eval()
        return torch.sigmoid(self.forward(padded, lengths))
