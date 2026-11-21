"""Matplotlib charts of the evaluation results (static PNGs, light surface)."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from evaluation.metrics import Row

SURFACE, INK, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e1e0d9"
BLUE, ORANGE, AQUA, LIGHT_BLUE = "#2a78d6", "#eb6834", "#1baf7a", "#86b6ef"


def _style(ax: plt.Axes, grid_axis: str) -> None:
    ax.set_facecolor(SURFACE)
    ax.grid(axis=grid_axis, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=MUTED, length=0)


def _save(fig: plt.Figure, path: Path) -> None:
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)


def plot_comparison(rows: list[Row], path: Path) -> None:
    """Grouped bars: precision, recall and F1 of every configuration."""
    metrics = (("Precision", BLUE), ("Recall", ORANGE), ("F1", AQUA))
    fig, ax = plt.subplots(figsize=(10, 4.5), facecolor=SURFACE)
    width = 0.26
    for i, (label, color) in enumerate(metrics):
        values = [getattr(r.scores, label.lower()) for r in rows]
        xs = [j + (i - 1) * width for j in range(len(rows))]
        bars = ax.bar(xs, values, width * 0.88, color=color, label=label)
        for bar, v in zip(bars, values, strict=True):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                v + 0.012,
                f"{v:.2f}",
                ha="center",
                va="bottom",
                fontsize=7,
                color=INK,
            )
    ax.set_xticks(range(len(rows)), [r.name.replace("+", "\n+") for r in rows], fontsize=8)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("score on the test corpus", color=MUTED)
    ax.set_title("Detection quality, held-out test corpus", loc="left", color=INK, fontsize=11)
    _style(ax, "y")
    ax.legend(frameon=False, ncols=3, loc="upper left", labelcolor=MUTED)
    _save(fig, path)


def plot_family_rates(
    before: dict[str, tuple[int, int]], after: dict[str, tuple[int, int]], path: Path
) -> None:
    """Horizontal bars: share of each decoy family flagged, without and with the classifier."""
    names = list(before)
    fig, ax = plt.subplots(figsize=(8, 0.42 * len(names) + 1.5), facecolor=SURFACE)
    height = 0.38
    for offset, data, color, label in (
        (-height / 2, before, LIGHT_BLUE, "without classifier"),
        (height / 2, after, BLUE, "with classifier"),
    ):
        rates = [data[n][0] / data[n][1] if data[n][1] else 0.0 for n in names]
        ys = [i + offset for i in range(len(names))]
        bars = ax.barh(ys, rates, height * 0.9, color=color, label=label)
        for bar, rate in zip(bars, rates, strict=True):
            ax.text(
                rate + 0.01,
                bar.get_y() + bar.get_height() / 2,
                f"{rate:.0%}",
                va="center",
                fontsize=7,
                color=INK,
            )
    ax.set_yticks(range(len(names)), names, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlim(0, 1.1)
    ax.set_xlabel("share of the decoys flagged (lower is better)", color=MUTED)
    ax.set_title("False positives by decoy family", loc="left", color=INK, fontsize=11)
    _style(ax, "x")
    ax.legend(frameon=False, loc="lower right", labelcolor=MUTED)
    _save(fig, path)
