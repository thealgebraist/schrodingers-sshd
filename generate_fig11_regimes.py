#!/usr/bin/env python3
import os
import numpy as np
import matplotlib.pyplot as plt
from math import comb

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
    "axes.edgecolor": "#334155",
    "axes.linewidth": 0.9,
})

PERIODIC_COLOR = [1, 2, 3, 4, 5, 3, 2, 1]
def switch_color(k):
    return PERIODIC_COLOR[k & 7]

def obst_cost(fw):
    n = len(fw)
    if n <= 1:
        return 0.0
    psum = [0.0] * (n + 1)
    for i in range(n):
        psum[i + 1] = psum[i] + fw[i]
    dp = [[0.0] * n for _ in range(n)]
    for length in range(2, n + 1):
        for l in range(0, n - length + 1):
            h = l + length - 1
            w_sub = psum[h + 1] - psum[l]
            best = 1e30
            for p in range(l, h):
                v = w_sub + dp[l][p] + dp[p + 1][h]
                if v < best:
                    best = v
            dp[l][h] = best
    return dp[0][n - 1]

def compute_bellman_curve(a_start, r, include_healthy_128=False):
    """Returns (ms, J_curve, m_star, min_J) for first probe threshold m in [a_start..127]."""
    w = [comb(127 - k, r - 1) if k >= a_start else 0.0 for k in range(128)]
    w_128 = 1.0 if include_healthy_128 else 0.0

    F = [0.0] * 129
    best_m = [127] * 129
    for i in range(127, a_start - 1, -1):
        rem_w = sum(w[i:128]) + w_128
        if rem_w <= 0:
            continue
        b_val = 1e30
        b_m = 127
        for m in range(i, 128):
            fail_c = 0.0
            for c in range(1, 6):
                fw = [w[k] for k in range(i, m + 1) if switch_color(k) == c]
                fail_c += obst_cost(fw)
            tot = rem_w + fail_c + F[m + 1]
            if tot < b_val - 1e-12:
                b_val = tot
                b_m = m
        F[i] = b_val
        best_m[i] = b_m

    total_w = sum(w[a_start:128]) + w_128
    ms = list(range(a_start, 128))
    J_curve = []
    for m in ms:
        fail_c = 0.0
        for c in range(1, 6):
            fw = [w[k] for k in range(a_start, m + 1) if switch_color(k) == c]
            fail_c += obst_cost(fw)
        tot = (total_w + fail_c + F[m + 1]) / total_w
        J_curve.append(tot)
    m_star = best_m[a_start]
    min_J = F[a_start] / total_w
    return ms, J_curve, m_star, min_J

fig = plt.figure(figsize=(15.6, 6.7), dpi=220)
gs = fig.add_gridspec(1, 2, width_ratios=[1.06, 1.14], wspace=0.23, left=0.055, right=0.975, top=0.835, bottom=0.14)

fig.suptitle(
    "Why Three Distinct 'Optimal' Solutions Exist: Oracle Coupling Regimes & Order-Statistic Pass-Chain DP",
    fontsize=13.4, fontweight="bold", color="#0f172a", y=0.955
)
fig.text(
    0.5, 0.903,
    "Regime I: Binary Prefix Only (905/129 = 7.02)   |   Regime II: Decoupled E2E-First + Binary Prefix (737/129 = 5.71)   |   Regime III: Coupled Prefix-Symptom DP (619/129 = 4.80; Order-Stat = 18–21 probes)",
    ha="center", fontsize=9.5, color="#334155", style="italic"
)

# ============================================================================
# PANEL A: Comparison of the 3 Optimal Oracle Regimes (+ Order-Stat DP & Claude)
# ============================================================================
ax1 = fig.add_subplot(gs[0, 0])

labels = [
    "Regime I:\nStage-Agnostic\nPrefix (Π)",
    "Regime II:\nDecoupled E2E\n+ Fiber (O⁻¹+Π)",
    "Regime IIIa:\nCoupled Uniform\nPass-Chain DP",
    "Claude Interactive\nOrder-Stat DP\n(Wave 1 @ 127)",
    "Regime IIIb:\nFull Order-Stat\nPass-Chain DP"
]

single_fault_5x = [5 * 905/129, 5 * 737/129, 5 * 619/129, 5 * 619/129, 5 * 619/129]
adv5_probes     = [38, 28, 23, 21, 18]
mc_5fault       = [35.56, 25.30, 22.24, 19.85, 17.19]

x = np.arange(len(labels))
w = 0.26

b1 = ax1.bar(x - w, adv5_probes, width=w, color="#1e40af", edgecolor="#0f172a", linewidth=0.8, label="Adversarial 5-Fault Instance (Probes)")
b2 = ax1.bar(x, mc_5fault, width=w, color="#0284c7", edgecolor="#0f172a", linewidth=0.8, label="10,000-Trial 5-Fault Monte Carlo Avg")
b3 = ax1.bar(x + w, single_fault_5x, width=w, color="#10b981", edgecolor="#0f172a", linewidth=0.8, alpha=0.85, label="5 × Single-Fault E[Probes] Reference")

for bar, val in zip(b1, adv5_probes):
    ax1.text(bar.get_x() + bar.get_width()/2, val + 0.65, f"{val}", ha="center", va="bottom", fontsize=8.8, fontweight="bold", color="#1e3a8a")

for i, (bar, val) in enumerate(zip(b2, mc_5fault)):
    y_off = 0.65 if i > 0 else 0.55
    ax1.text(bar.get_x() + bar.get_width()/2 - (0.04 if i == 0 else 0.0), val + y_off, f"{val:.1f}", ha="center", va="bottom", fontsize=8.1, fontweight="bold", color="#0369a1")

sf_fractions = ["905/129\n(7.02/flt)", "737/129\n(5.71/flt)", "619/129\n(4.80/flt)", "Prior:\nC(127-k,r-1)", "Prior:\nC(127-k,r-1)"]
for idx, (bar, txt) in enumerate(zip(b3, sf_fractions)):
    x_shift = 0.07 if idx == 0 else 0.0
    y_shift = 1.65 if idx == 0 else 0.55
    ax1.text(bar.get_x() + bar.get_width()/2 + x_shift, bar.get_height() + y_shift, txt, ha="center", va="bottom", fontsize=7.1, color="#065f46", fontweight="bold")

ax1.set_xticks(x)
ax1.set_xticklabels(labels, fontsize=8.3, fontweight="bold", color="#1e293b")
ax1.set_ylabel("Total Epistemic Probes (0 Wrong Repairs)", fontsize=9.8, fontweight="bold", color="#0f172a")
ax1.set_ylim(0, 44.5)
ax1.grid(axis="y", linestyle="--", alpha=0.45)
ax1.set_title("A. Exact Probe Complexity Across the Three Optimal Regimes", fontsize=10.6, fontweight="bold", color="#0f172a", pad=10)
ax1.legend(loc="upper right", fontsize=7.9, framealpha=0.94)

# ============================================================================
# PANEL B: Exact Bellman Expected Cost J_r(a, m) vs. First Probe Threshold m
# ============================================================================
ax2 = fig.add_subplot(gs[0, 1])

ms_u, J_u, m_u, min_u   = compute_bellman_curve(0, 1, include_healthy_128=True)
ms_w1, J_w1, m_w1, min_w1 = compute_bellman_curve(0, 5, include_healthy_128=False)
ms_w2, J_w2, m_w2, min_w2 = compute_bellman_curve(2, 4, include_healthy_128=False)
ms_w3, J_w3, m_w3, min_w3 = compute_bellman_curve(25, 3, include_healthy_128=False)
ms_w4, J_w4, m_w4, min_w4 = compute_bellman_curve(60, 2, include_healthy_128=False)
ms_w5, J_w5, m_w5, min_w5 = compute_bellman_curve(94, 1, include_healthy_128=False)

ax2.plot(ms_u, J_u, color="#0f766e", lw=2.3, label=f"Regime IIIa Uniform (a=0, 129 states): min at m*={m_u} ({min_u:.2f} vs 5.71 @ 127)")
ax2.plot(ms_w1, J_w1, color="#1d4ed8", lw=1.8, linestyle="--", label=f"Wave 1 Order-Stat (a=0, r=5): min at m*={m_w1} ({min_w1:.2f} probes)")
ax2.plot(ms_w2, J_w2, color="#dc2626", lw=2.0, label=f"Claude Wave 2 (a=2, r=4): min at m*={m_w2} ({min_w2:.2f} probes)")
ax2.plot(ms_w3, J_w3, color="#0891b2", lw=2.0, label=f"Claude Wave 3 (a=25, r=3): min at m*={m_w3} ({min_w3:.2f} probes)")
ax2.plot(ms_w4, J_w4, color="#d97706", lw=2.0, label=f"Claude Wave 4 (a=60, r=2): min at m*={m_w4} ({min_w4:.2f} probes)")
ax2.plot(ms_w5, J_w5, color="#7c3aed", lw=2.0, label=f"Claude Wave 5 (a=94, r=1): min at m*={m_w5} ({min_w5:.2f} probes)")

annots = [
    (m_u, min_u, "#0f766e", f"m*={m_u}\n619/129=4.80", (m_u - 10, min_u + 0.55)),
    (127, J_u[-1], "#334155", f"m=127 (Regime II)\n737/129=5.71", (95, 5.92)),
    (m_w1, min_w1, "#1d4ed8", f"W1: m*={m_w1}\n({min_w1:.2f}p)", (2, 3.12)),
    (m_w2, min_w2, "#dc2626", f"Claude W2:\nm*={m_w2} ({min_w2:.2f}p)", (22, 3.05)),
    (m_w3, min_w3, "#0891b2", f"Claude W3:\nm*={m_w3} ({min_w3:.2f}p)", (44, 3.08)),
    (m_w4, min_w4, "#d97706", f"Claude W4:\nm*={m_w4} ({min_w4:.2f}p)", (72, 2.98)),
    (m_w5, min_w5, "#7c3aed", f"Claude W5:\nm*={m_w5} ({min_w5:.2f}p)", (102, 2.50)),
]

for mx, my, col, txt, (tx, ty) in annots:
    ax2.scatter([mx], [my], color=col, s=52, zorder=6, edgecolors="#0f172a", linewidth=0.9)
    ax2.annotate(
        txt, xy=(mx, my), xytext=(tx, ty),
        fontsize=7.5, fontweight="bold", color=col,
        arrowprops=dict(arrowstyle="->", color=col, lw=1.0),
        bbox=dict(boxstyle="round,pad=0.2", fc="#f8fafc", ec=col, lw=0.8)
    )

ax2.set_xlabel("First Probe Threshold Choice m ∈ [a..127] in Current Wave", fontsize=9.8, fontweight="bold", color="#0f172a")
ax2.set_ylabel("Bellman Expected Probes per Wave J_r(a, m)", fontsize=9.8, fontweight="bold", color="#0f172a")
ax2.set_xlim(-3, 132)
ax2.set_ylim(2.25, 6.45)
ax2.grid(True, linestyle="--", alpha=0.45)
ax2.set_title("B. Bellman Cost Landscapes J_r(a, m): Why Intermediate m* < 127 Is Strictly Optimal", fontsize=10.4, fontweight="bold", color="#0f172a", pad=10)
ax2.legend(loc="upper left", fontsize=7.25, framealpha=0.94)

out_dir = "/Users/anders/.gemini/antigravity/scratch/cascaded_diag_c99/figures"
brain_dir = "/Users/anders/.gemini/antigravity/brain/6bb4444d-9f46-49da-a4cd-bae6450c6f14/figures"
os.makedirs(out_dir, exist_ok=True)
os.makedirs(brain_dir, exist_ok=True)
plt.savefig(f"{out_dir}/fig11_three_optimal_regimes_and_claude_dp.png", dpi=220)
plt.savefig(f"{brain_dir}/fig11_three_optimal_regimes_and_claude_dp.png", dpi=220)
print("Saved updated fig11_three_optimal_regimes_and_claude_dp.png")
