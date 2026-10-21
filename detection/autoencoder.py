"""
Autoencoder Neural Network for Windows Telemetry Anomaly Detection.

Architecture:
- Encoder: Input -> Dense(64, ReLU) -> BatchNorm -> Dropout(0.1) -> Dense(32, ReLU) -> Latent(16)
- Decoder: Latent(16) -> Dense(32, ReLU) -> BatchNorm -> Dense(64, ReLU) -> Output(N, Sigmoid/Linear)
"""
from __future__ import annotations

import torch
import torch.nn as nn


class TelemetryAutoencoder(nn.Module):
    """Deep Autoencoder for multivariate anomaly detection."""

    def __init__(self, input_dim: int, latent_dim: int = 16) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.latent_dim = latent_dim

        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.1),
            nn.Dropout(0.05),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.1),
            nn.Linear(32, latent_dim),
        )

        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.1),
            nn.Linear(32, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.1),
            nn.Linear(64, input_dim),
            nn.Sigmoid(),  # Assumes MinMaxScaler normalization in range [0, 1]
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        latent = self.encoder(x)
        reconstruction = self.decoder(latent)
        return reconstruction

    def compute_reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Compute sample-wise Mean Squared Error (reconstruction error)."""
        reconstruction = self.forward(x)
        # MSE per sample
        mse = torch.mean((x - reconstruction) ** 2, dim=1)
        return mse
