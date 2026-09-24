"""
Mini SIEM — Security Dashboard Generator
=========================================

Produces a multi-panel visual security dashboard from SIEM analysis results
using matplotlib. Output is a single PNG suitable for SOC briefings and
incident reports.

Dashboard Panels:
  1. Top Threat Sources       — Bar chart of IPs by failed attempt count
  2. Alert Severity Breakdown — Pie chart of LOW / MEDIUM / HIGH distribution
  3. Attack Timeline          — Hourly failed-login volume over time
  4. Targeted Services        — Horizontal bar chart of services under attack
"""

import os
from typing import Dict

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless rendering

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker


# Cybersecurity-themed color palette
COLORS = {
    "HIGH":    "#e74c3c",   # Red
    "MEDIUM":  "#f39c12",   # Amber
    "LOW":     "#f1c40f",   # Yellow
    "INFO":    "#95a5a6",   # Grey
    "bar":     "#2ecc71",   # Green
    "accent":  "#3498db",   # Blue
    "bg":      "#1a1a2e",   # Dark navy
    "panel":   "#16213e",   # Panel background
    "text":    "#e0e0e0",   # Light text
    "grid":    "#2c3e6e",   # Grid lines
}

SEVERITY_COLORS = [COLORS["HIGH"], COLORS["MEDIUM"], COLORS["LOW"]]


def generate_dashboard(result, output_path: str = "reports/dashboard.png") -> str:
    """
    Generate a 4-panel security dashboard from SIEM analysis results.

    Args:
        result:      An AnalysisResult object from SIEMAnalyzer.
        output_path: Destination path for the dashboard PNG.

    Returns:
        Absolute path to the saved dashboard image.
    """
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    # Apply dark cybersecurity theme
    plt.rcParams.update({
        "figure.facecolor": COLORS["bg"],
        "axes.facecolor":   COLORS["panel"],
        "axes.edgecolor":   COLORS["grid"],
        "axes.labelcolor":  COLORS["text"],
        "text.color":       COLORS["text"],
        "xtick.color":      COLORS["text"],
        "ytick.color":      COLORS["text"],
        "grid.color":       COLORS["grid"],
        "grid.alpha":       0.3,
        "font.family":      "monospace",
        "font.size":        9,
    })

    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle(
        "MINI SIEM — SECURITY MONITORING DASHBOARD",
        fontsize=16, fontweight="bold", color="#00ff88", y=0.98,
    )

    # ── Panel 1: Top Threat Sources (Top 10 IPs by failures) ──
    ax1 = axes[0, 0]
    _plot_top_threat_sources(ax1, result.ip_failure_counts, result.alerts)

    # ── Panel 2: Alert Severity Distribution ──
    ax2 = axes[0, 1]
    _plot_severity_distribution(ax2, result.severity_counts)

    # ── Panel 3: Attack Timeline (hourly) ──
    ax3 = axes[1, 0]
    _plot_attack_timeline(ax3, result.hourly_failures)

    # ── Panel 4: Targeted Services ──
    ax4 = axes[1, 1]
    _plot_targeted_services(ax4, result.service_failure_counts)

    # Summary footer
    footer = (
        f"Total Events: {result.total_events:,}  │  "
        f"Failures: {result.total_failures:,}  │  "
        f"Unique IPs: {result.unique_source_ips:,}  │  "
        f"Alerts Generated: {len(result.alerts)}  │  "
        f"Analysis Window: "
        f"{result.analysis_window_start.strftime('%Y-%m-%d %H:%M') if result.analysis_window_start else 'N/A'}"
        f" → "
        f"{result.analysis_window_end.strftime('%Y-%m-%d %H:%M') if result.analysis_window_end else 'N/A'}"
    )
    fig.text(0.5, 0.01, footer, ha="center", fontsize=8,
             color="#00ff88", fontstyle="italic")

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    fig.savefig(output_path, dpi=150, bbox_inches="tight",
                facecolor=COLORS["bg"], edgecolor="none")
    plt.close(fig)

    return os.path.abspath(output_path)


# ──────────────────────────────────────────────
#  Individual Panel Renderers
# ──────────────────────────────────────────────

def _plot_top_threat_sources(ax, ip_failure_counts: Dict[str, int], alerts):
    """Bar chart: Top 10 source IPs by total failed authentication attempts."""
    sorted_ips = sorted(ip_failure_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    if not sorted_ips:
        ax.text(0.5, 0.5, "No threat sources detected",
                ha="center", va="center", fontsize=12, color=COLORS["text"])
        ax.set_title("TOP THREAT SOURCES", fontweight="bold", color="#00ff88")
        return

    ips = [ip for ip, _ in sorted_ips]
    counts = [count for _, count in sorted_ips]

    # Color bars by whether the IP generated an alert
    alerted_ips = {a.source_ip for a in alerts}
    bar_colors = []
    for ip in ips:
        if ip in alerted_ips:
            # Find the alert severity for this IP
            alert = next((a for a in alerts if a.source_ip == ip), None)
            if alert:
                bar_colors.append(COLORS.get(alert.severity, COLORS["bar"]))
            else:
                bar_colors.append(COLORS["bar"])
        else:
            bar_colors.append(COLORS["accent"])

    bars = ax.barh(range(len(ips)), counts, color=bar_colors, edgecolor="#0a0a1a", linewidth=0.5)
    ax.set_yticks(range(len(ips)))
    ax.set_yticklabels(ips, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("Failed Attempts")
    ax.set_title("TOP THREAT SOURCES (by failed logins)", fontweight="bold", color="#00ff88")
    ax.grid(axis="x", alpha=0.2)

    # Add count labels on bars
    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                str(count), va="center", fontsize=8, color=COLORS["text"])


def _plot_severity_distribution(ax, severity_counts: Dict[str, int]):
    """Pie chart: Alert severity breakdown."""
    if not severity_counts:
        ax.text(0.5, 0.5, "No alerts generated",
                ha="center", va="center", fontsize=12, color=COLORS["text"])
        ax.set_title("ALERT SEVERITY DISTRIBUTION", fontweight="bold", color="#00ff88")
        return

    # Ensure consistent ordering: HIGH, MEDIUM, LOW
    ordered_severities = ["HIGH", "MEDIUM", "LOW"]
    labels = []
    sizes = []
    colors = []

    for sev in ordered_severities:
        if sev in severity_counts and severity_counts[sev] > 0:
            labels.append(sev)
            sizes.append(severity_counts[sev])
            colors.append(COLORS[sev])

    if not sizes:
        ax.text(0.5, 0.5, "No alerts generated",
                ha="center", va="center", fontsize=12, color=COLORS["text"])
        ax.set_title("ALERT SEVERITY DISTRIBUTION", fontweight="bold", color="#00ff88")
        return

    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, autopct="%1.0f%%",
        startangle=90, pctdistance=0.75,
        wedgeprops={"edgecolor": COLORS["bg"], "linewidth": 2},
    )
    for txt in texts:
        txt.set_color(COLORS["text"])
        txt.set_fontweight("bold")
    for atxt in autotexts:
        atxt.set_color("#1a1a2e")
        atxt.set_fontweight("bold")

    ax.set_title("ALERT SEVERITY DISTRIBUTION", fontweight="bold", color="#00ff88")


def _plot_attack_timeline(ax, hourly_failures: Dict[str, int]):
    """Line/bar chart: Hourly failed login volume over time."""
    if not hourly_failures:
        ax.text(0.5, 0.5, "No failures recorded",
                ha="center", va="center", fontsize=12, color=COLORS["text"])
        ax.set_title("ATTACK TIMELINE (hourly failures)", fontweight="bold", color="#00ff88")
        return

    sorted_hours = sorted(hourly_failures.items())
    labels = [h for h, _ in sorted_hours]
    counts = [c for _, c in sorted_hours]

    ax.fill_between(range(len(labels)), counts, alpha=0.3, color=COLORS["HIGH"])
    ax.plot(range(len(labels)), counts, color=COLORS["HIGH"],
            linewidth=1.5, marker=".", markersize=3)

    # Show subset of x labels to avoid overlap
    step = max(1, len(labels) // 12)
    ax.set_xticks(range(0, len(labels), step))
    ax.set_xticklabels(
        [labels[i].split(" ")[1] if " " in labels[i] else labels[i]
         for i in range(0, len(labels), step)],
        rotation=45, fontsize=7,
    )

    ax.set_xlabel("Time (hourly buckets)")
    ax.set_ylabel("Failed Attempts")
    ax.set_title("ATTACK TIMELINE (hourly failures)", fontweight="bold", color="#00ff88")
    ax.grid(axis="y", alpha=0.2)


def _plot_targeted_services(ax, service_failure_counts: Dict[str, int]):
    """Horizontal bar chart: Services targeted by failed logins."""
    if not service_failure_counts:
        ax.text(0.5, 0.5, "No service data",
                ha="center", va="center", fontsize=12, color=COLORS["text"])
        ax.set_title("TARGETED SERVICES", fontweight="bold", color="#00ff88")
        return

    sorted_services = sorted(service_failure_counts.items(),
                             key=lambda x: x[1], reverse=True)
    services = [s for s, _ in sorted_services]
    counts = [c for _, c in sorted_services]

    # Gradient colors
    cmap = plt.cm.YlOrRd
    norm_counts = [c / max(counts) for c in counts]
    bar_colors = [cmap(0.3 + 0.6 * n) for n in norm_counts]

    bars = ax.barh(range(len(services)), counts, color=bar_colors,
                   edgecolor="#0a0a1a", linewidth=0.5)
    ax.set_yticks(range(len(services)))
    ax.set_yticklabels(services, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("Failed Attempts")
    ax.set_title("TARGETED SERVICES", fontweight="bold", color="#00ff88")
    ax.grid(axis="x", alpha=0.2)

    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                str(count), va="center", fontsize=8, color=COLORS["text"])


# ══════════════════════════════════════════════════════════
#  Standalone execution
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    from siem_analyzer import SIEMAnalyzer

    analyzer = SIEMAnalyzer()
    result = analyzer.analyze("data/auth_logs.csv")
    path = generate_dashboard(result)
    print(f"[+] Dashboard saved → {path}")
