"""
detection/trainer.py
====================
Training loop for TelemetryAutoencoder.

Features:
- Trains ONLY on normal samples (label=0) — semi-supervised one-class learning.
- Adam optimizer with cosine-annealing LR schedule.
- MSE reconstruction loss.
- Early stopping (patience configurable).
- Best-model checkpoint saved to models/autoencoder.pt.
- Per-epoch loss written to models/training_history.json.
- CUDA-first; falls back to CPU if GPU unavailable.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from config.settings import settings
from detection.autoencoder import TelemetryAutoencoder

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_device() -> torch.device:
    """Return the best available device (CUDA > CPU)."""
    if torch.cuda.is_available():
        device = torch.device("cuda")
        props = torch.cuda.get_device_properties(0)
        logger.info(
            "Using GPU: %s  (%.1f GB VRAM)",
            props.name,
            props.total_memory / 1e9,
        )
    else:
        device = torch.device("cpu")
        logger.warning("CUDA not available — training on CPU (will be slow).")
    return device


def _build_dataloaders(
    X_normal: np.ndarray,
    val_fraction: float = 0.1,
    batch_size: int = 256,
    seed: int = 42,
) -> tuple[DataLoader, DataLoader]:
    """Split X_normal into train/val and return DataLoaders."""
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(X_normal))
    n_val = max(1, int(len(X_normal) * val_fraction))
    val_idx, train_idx = idx[:n_val], idx[n_val:]

    X_train = torch.tensor(X_normal[train_idx], dtype=torch.float32)
    X_val = torch.tensor(X_normal[val_idx], dtype=torch.float32)

    train_loader = DataLoader(
        TensorDataset(X_train, X_train),
        batch_size=batch_size,
        shuffle=True,
        pin_memory=torch.cuda.is_available(),
        num_workers=0,
    )
    val_loader = DataLoader(
        TensorDataset(X_val, X_val),
        batch_size=batch_size,
        shuffle=False,
        pin_memory=torch.cuda.is_available(),
        num_workers=0,
    )
    logger.info(
        "Train samples: %d  |  Val samples: %d",
        len(train_idx),
        len(val_idx),
    )
    return train_loader, val_loader


# ---------------------------------------------------------------------------
# Main trainer
# ---------------------------------------------------------------------------

class AutoencoderTrainer:
    """
    Manages the full training lifecycle for TelemetryAutoencoder.

    Parameters
    ----------
    input_dim : int
        Number of input features (must match preprocessor output).
    epochs : int
        Maximum training epochs.
    batch_size : int
        Mini-batch size.
    lr : float
        Initial Adam learning rate.
    patience : int
        Early-stopping patience (epochs without val-loss improvement).
    val_fraction : float
        Fraction of normal samples held out for validation.
    checkpoint_path : Path | None
        Where to save the best model. Defaults to settings.model_path.
    """

    def __init__(
        self,
        input_dim: int,
        epochs: int = 80,
        batch_size: int = 256,
        lr: float = 1e-3,
        patience: int = 12,
        val_fraction: float = 0.1,
        checkpoint_path: Optional[Path] = None,
    ) -> None:
        self.input_dim = input_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = lr
        self.patience = patience
        self.val_fraction = val_fraction
        self.checkpoint_path: Path = checkpoint_path or settings.model_path
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

        self.device = _get_device()
        self.model = TelemetryAutoencoder(input_dim=input_dim).to(self.device)
        self.history: list[dict] = []

    # ------------------------------------------------------------------
    def train(self, X_normal: np.ndarray) -> dict:
        """
        Train the autoencoder on `X_normal` (already scaled, shape [N, input_dim]).

        Returns
        -------
        dict
            Training summary with best_val_loss, epochs_trained, elapsed_seconds.
        """
        train_loader, val_loader = _build_dataloaders(
            X_normal,
            val_fraction=self.val_fraction,
            batch_size=self.batch_size,
        )

        optimizer = torch.optim.Adam(self.model.parameters(), lr=self.lr, weight_decay=1e-5)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=self.epochs, eta_min=1e-5
        )
        criterion = nn.MSELoss()

        best_val_loss = float("inf")
        patience_counter = 0
        t0 = time.time()

        logger.info(
            "Starting training: input_dim=%d  epochs=%d  batch=%d  device=%s",
            self.input_dim,
            self.epochs,
            self.batch_size,
            self.device,
        )

        for epoch in range(1, self.epochs + 1):
            # ---- Train ----
            self.model.train()
            train_loss = 0.0
            for X_batch, y_batch in train_loader:
                X_batch = X_batch.to(self.device, non_blocking=True)
                optimizer.zero_grad()
                recon = self.model(X_batch)
                loss = criterion(recon, X_batch)
                loss.backward()
                nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                optimizer.step()
                train_loss += loss.item() * len(X_batch)
            train_loss /= len(train_loader.dataset)

            # ---- Validate ----
            self.model.eval()
            val_loss = 0.0
            with torch.no_grad():
                for X_batch, y_batch in val_loader:
                    X_batch = X_batch.to(self.device, non_blocking=True)
                    recon = self.model(X_batch)
                    loss = criterion(recon, X_batch)
                    val_loss += loss.item() * len(X_batch)
            val_loss /= len(val_loader.dataset)

            scheduler.step()
            current_lr = scheduler.get_last_lr()[0]

            self.history.append(
                {
                    "epoch": epoch,
                    "train_loss": round(train_loss, 8),
                    "val_loss": round(val_loss, 8),
                    "lr": round(current_lr, 8),
                }
            )

            if epoch % 5 == 0 or epoch == 1:
                logger.info(
                    "Epoch %3d/%d  train_loss=%.6f  val_loss=%.6f  lr=%.2e",
                    epoch,
                    self.epochs,
                    train_loss,
                    val_loss,
                    current_lr,
                )

            # ---- Early stopping ----
            if val_loss < best_val_loss - 1e-7:
                best_val_loss = val_loss
                patience_counter = 0
                self._save_checkpoint()
            else:
                patience_counter += 1
                if patience_counter >= self.patience:
                    logger.info(
                        "Early stopping at epoch %d (patience=%d)",
                        epoch,
                        self.patience,
                    )
                    break

        elapsed = time.time() - t0
        self._save_history()

        summary = {
            "best_val_loss": round(best_val_loss, 8),
            "epochs_trained": len(self.history),
            "elapsed_seconds": round(elapsed, 2),
            "input_dim": self.input_dim,
            "device": str(self.device),
            "checkpoint_path": str(self.checkpoint_path),
        }
        logger.info(
            "Training complete. best_val_loss=%.6f  time=%.1fs  checkpoint=%s",
            best_val_loss,
            elapsed,
            self.checkpoint_path,
        )
        return summary

    # ------------------------------------------------------------------
    def _save_checkpoint(self) -> None:
        """Save model weights to checkpoint_path."""
        torch.save(
            {
                "model_state_dict": self.model.state_dict(),
                "input_dim": self.input_dim,
                "architecture": {
                    "encoder_dims": [64, 32, 16],
                    "decoder_dims": [32, 64],
                },
            },
            self.checkpoint_path,
        )

    def _save_history(self) -> None:
        """Persist per-epoch loss history to models/training_history.json."""
        history_path = self.checkpoint_path.parent / "training_history.json"
        with open(history_path, "w", encoding="utf-8") as f:
            json.dump(self.history, f, indent=2)
        logger.info("Training history saved → %s", history_path)

    # ------------------------------------------------------------------
    @classmethod
    def load_checkpoint(cls, checkpoint_path: Optional[Path] = None) -> "TelemetryAutoencoder":
        """
        Load a saved autoencoder from checkpoint.

        Parameters
        ----------
        checkpoint_path : Path | None
            Path to .pt file. Defaults to settings.model_path.

        Returns
        -------
        TelemetryAutoencoder (on best available device, eval mode)
        """
        path = checkpoint_path or settings.model_path
        if not path.exists():
            raise FileNotFoundError(f"No checkpoint found at {path}")

        ckpt = torch.load(path, map_location="cpu", weights_only=False)
        input_dim = ckpt["input_dim"]
        model = TelemetryAutoencoder(input_dim=input_dim)
        model.load_state_dict(ckpt["model_state_dict"])
        device = _get_device()
        model = model.to(device)
        model.eval()
        logger.info("Loaded autoencoder from %s (input_dim=%d)", path, input_dim)
        return model
