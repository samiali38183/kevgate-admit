"""Render docs/img/hero-e2e.png from the saved CI transcripts in docs/E2E.md.

    pip install matplotlib
    python scripts/make_hero.py

The workload outcomes, rules and risk scores are parsed from the transcript of the `e2e-kind` workflow.
"""

from __future__ import annotations

import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TRANSCRIPT = ROOT / "docs" / "E2E.md"
OUT = ROOT / "docs" / "img" / "hero-e2e.png"
INK, MUTED, LINE = "#111827", "#4b5563", "#d1d5db"
GREEN, RED, AMBER = "#15803d", "#b91c1c", "#b45309"
plt.rcParams["font.family"] = ["Segoe UI", "DejaVu Sans"]

OUTCOME = {"allowed": ("ALLOWED", GREEN), "denied": ("DENIED", RED), "warned": ("WARNED", AMBER)}


def parse_demo(text: str) -> list[dict]:
    """One entry per `== name in namespace (expect: outcome)` block in the install/allow/deny/warn transcript."""
    demo = text.split("## Failure modes")[0]
    rows = []
    for block in re.split(r"\n(?=== )", demo):
        head = re.match(r"== (\S+) in (\S+) \(expect: (\w+)\)", block)
        if not head:
            continue
        name, ns, outcome = head.groups()
        assert re.search(r"RESULT %s: PASS" % re.escape(name), block), name
        rules = re.findall(r"^- \[(\w+)\]", block, re.M) or re.findall(r"would deny \[(\w+)\]", block)
        scores = [float(x) for x in re.findall(r"risk\s+(\d+\.\d)", block)]
        cve = re.search(r"(CVE-[\d-]+)\s+KEV", block)
        limit = re.search(r"above max risk ([\d.]+) \(highest ([\d.]+)\)", block)
        scores = scores or ([float(limit.group(2))] if limit else [])
        rows.append({"name": name, "ns": ns, "outcome": outcome,
                     "rules": rules, "scores": scores, "kev_cve": cve.group(1) if cve else None, "limit": limit})
    return rows


def why(r: dict) -> str:
    if r["outcome"] == "allowed":
        return "no KEV finding, digest pinned"
    parts = []
    if "denyKev" in r["rules"] and r["kev_cve"]:
        parts.append("%s is in CISA KEV, risk %.1f" % (r["kev_cve"], max(r["scores"])))
    if "maxRisk" in r["rules"] and r["limit"] and "denyKev" not in r["rules"]:
        parts.append("risk %s is over the limit of %s" % (r["limit"].group(2), r["limit"].group(1)))
    if "requireDigest" in r["rules"]:
        parts.append("image is a tag, not a digest (tags can change)")
    text = "; ".join(parts)
    return ("admitted with a warning (audit mode): " + text) if r["outcome"] == "warned" else text


def box(ax, x, y, w, h, fc, ec):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.01", fc=fc, ec=ec, lw=1.5))


def main() -> None:
    text = TRANSCRIPT.read_text(encoding="utf-8")
    rows = parse_demo(text)
    outage = text.split("## Failure modes")[1]
    n_demo = len(rows)
    n_outage = len(re.findall(r"^RESULT .*: PASS", outage, re.M))
    assert "RESULT fail-policy-rejects: PASS" in outage and "RESULT ignore-policy-admits-tag-only-pod: PASS" in outage
    assert "RESULT resumed-deny-kev: PASS" in outage

    fig = plt.figure(figsize=(9, 5.6), dpi=200, facecolor="white")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.text(0.03, 0.93, "Which workloads does the cluster let in?", fontsize=19, weight="bold", color=INK)
    ax.text(0.03, 0.865, "A webhook checks every container image against known-exploited vulnerabilities before Kubernetes starts it.",
            fontsize=11, color=MUTED)

    ax.text(0.03, 0.80, "Five workloads applied to a real cluster (kind, in GitHub Actions)", fontsize=11.5, weight="bold", color=MUTED)
    y = 0.745
    for r in rows:
        label, color = OUTCOME[r["outcome"]]
        ax.add_patch(plt.Rectangle((0.03, y - 0.047), 0.012, 0.058, fc=color, ec="none"))
        ax.text(0.055, y - 0.018, r["name"], fontsize=11.5, weight="bold", color=INK, va="center")
        ax.text(0.055, y - 0.045, "namespace " + r["ns"], fontsize=8.5, color=MUTED, va="center")
        ax.text(0.30, y - 0.018, label, fontsize=12.5, weight="bold", color=color, va="center")
        ax.text(0.445, y - 0.018, why(r), fontsize=10, color=INK, va="center")
        y -= 0.082

    ax.text(0.03, 0.295, "Then the webhook itself goes down", fontsize=11.5, weight="bold", color=MUTED)
    box(ax, 0.03, 0.165, 0.45, 0.10, "#f3f4f6", LINE)
    ax.text(0.045, 0.240, "failurePolicy: Fail", fontsize=11, weight="bold", color=INK, va="center")
    ax.text(0.045, 0.196, "New Pods are rejected until it is back", fontsize=10, color=INK, va="center")
    box(ax, 0.52, 0.165, 0.45, 0.10, "#fffbeb", AMBER)
    ax.text(0.535, 0.240, "failurePolicy: Ignore", fontsize=11, weight="bold", color=AMBER, va="center")
    ax.text(0.535, 0.196, "A Pod the policy would deny gets in", fontsize=10, color=INK, va="center")

    ax.plot([0.03, 0.97], [0.125, 0.125], color=LINE, lw=1)
    ax.text(0.03, 0.088, "%d of %d demo checks and %d of %d outage checks pass in the CI run. All scan data is synthetic."
            % (n_demo, n_demo, n_outage, n_outage), fontsize=10.5, color=INK, va="center", weight="bold")
    ax.text(0.03, 0.05, "Transcripts: docs/E2E.md. The webhook does not scan images itself and does not verify image signatures at admission.",
            fontsize=9.3, color=MUTED, va="center")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=200, facecolor="white")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
