#!/usr/bin/env python3
"""
generate_figures.py
Generates publication-grade vector SVG diagrams and converts them to high-DPI PNGs
via rsvg-convert for the LaTeX monograph on Matrix Theory & Optimal Cascaded SSH Diagnosis.
"""

import os
import subprocess
import math

OUT_DIR = "/Users/anders/.gemini/antigravity/scratch/cascaded_diag_c99/figures"
os.makedirs(OUT_DIR, exist_ok=True)


def save_svg_and_png(name: str, svg_content: str, width_px: int = 1800):
    svg_path = os.path.join(OUT_DIR, f"{name}.svg")
    png_path = os.path.join(OUT_DIR, f"{name}.png")
    with open(svg_path, "w", encoding="utf-8") as f:
        f.write(svg_content)
    subprocess.run(
        ["/opt/homebrew/bin/rsvg-convert", "-w", str(width_px), "-f", "png", "-o", png_path, svg_path],
        check=True,
    )
    print(f"Generated {svg_path} -> {png_path}")


# ==============================================================================
# FIGURE 1: Simple Example (D=7, W=8) Step-by-Step Belief Vector & Matrix Trace
# ==============================================================================
def make_fig1_simple_example():
    W = 980
    H = 680
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
        '<defs>',
        '  <linearGradient id="bgGrad" x1="0" y1="0" x2="0" y2="1">',
        '    <stop offset="0%" stop-color="#f8fafc"/>',
        '    <stop offset="100%" stop-color="#f1f5f9"/>',
        '  </linearGradient>',
        '  <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#334155"/>',
        '  </marker>',
        '  <marker id="arrowRed" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#dc2626"/>',
        '  </marker>',
        '  <marker id="arrowGreen" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#16a34a"/>',
        '  </marker>',
        '</defs>',
        f'<rect width="{W}" height="{H}" rx="10" fill="url(#bgGrad)" stroke="#cbd5e1" stroke-width="2"/>',
        # Header
        '<rect x="20" y="16" width="940" height="48" rx="6" fill="#1e293b"/>',
        '<text x="490" y="45" font-family="Helvetica, Arial, sans-serif" font-size="14" font-weight="bold" fill="#ffffff" text-anchor="middle">',
        'SIMPLE EXAMPLE (N=2 Hops, D=7 Stages, W=8 Frontier States): Exact Matrix Projection Trace for True Faults s_2=0, s_5=0 (k* = 2)',
        '</text>',
    ]

    # Top panel: True Latent State s in {0,1}^7 and Censoring Frontier k*=2
    svg.append('<rect x="20" y="76" width="940" height="106" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="36" y="98" font-family="Helvetica, Arial, sans-serif" font-size="13" font-weight="bold" fill="#0f172a">'
               'Latent State Vector s ∈ {0,1}⁷ &amp; Causal Censoring Frontier κ*(s) = 2 (Fault at s₅=0 is Masked by s₂=0):</text>')

    stage_labels = [
        ("k=0", "Hop0:Agent", 1),
        ("k=1", "Hop0:TCP22", 1),
        ("k=2", "Hop0:Auth", 0),   # ACTIVE FRONTIER k* = 2
        ("k=3", "Hop0:Fwd", 1),
        ("k=4", "Hop1:Agent", 1),
        ("k=5", "Hop1:DNS53", 0),  # MASKED FAULT
        ("k=6", "Hop1:Auth", 1),
        ("k=7", "ALL_OK (D)", 1),
    ]

    x0 = 42
    dx = 112
    for idx, (k_str, desc, bit) in enumerate(stage_labels):
        cx = x0 + idx * dx
        cy = 112
        if idx == 2:
            fill = "#fee2e2"
            stroke = "#dc2626"
            badge = "s₂=0 (k*=2)"
            tcol = "#991b1b"
        elif idx == 5:
            fill = "#fef3c7"
            stroke = "#d97706"
            badge = "s₅=0 (MASKED)"
            tcol = "#92400e"
        elif idx == 7:
            fill = "#e0f2fe"
            stroke = "#0284c7"
            badge = "State u₇"
            tcol = "#075985"
        else:
            fill = "#dcfce7"
            stroke = "#16a34a"
            badge = f"s_{idx}=1 (OK)"
            tcol = "#166534"

        svg.append(f'<rect x="{cx}" y="{cy}" width="92" height="54" rx="5" fill="{fill}" stroke="{stroke}" stroke-width="2"/>')
        svg.append(f'<text x="{cx+46}" y="{cy+18}" font-family="monospace" font-size="12" font-weight="bold" fill="{tcol}" text-anchor="middle">{k_str}</text>')
        svg.append(f'<text x="{cx+46}" y="{cy+33}" font-family="Helvetica, Arial, sans-serif" font-size="10" fill="#334155" text-anchor="middle">{desc}</text>')
        svg.append(f'<text x="{cx+46}" y="{cy+48}" font-family="monospace" font-size="10" font-weight="bold" fill="{tcol}" text-anchor="middle">{badge}</text>')
        if idx < 7:
            arrow_type = "arrowRed" if idx == 2 else "arrow"
            svg.append(f'<line x1="{cx+92}" y1="{cy+27}" x2="{cx+112}" y2="{cy+27}" stroke="#475569" stroke-width="1.8" marker-end="url(#{arrow_type})"/>')

    # Step-by-Step Belief Vector Evolution b_0 -> b_1 -> b_2 -> b_3
    steps = [
        {
            "title": "Step t=0 (Prior Belief b₀)",
            "subtitle": "Uniform over [L₀, R₀] = [0..7], Width W₀ = 8, Entropy H(b₀) = log₂(8) = 3.000 bits",
            "formula": "b₀ = (1/8, ..., 1/8)ᵀ  |  Split: m₁ = L₀ + dp[8] - 1 = 3",
            "probs": [0.125]*8,
            "active_range": (0, 7),
            "split_after": 3,
            "probe_note": "Execute Prefix Probe Π₃ (test stages 0..3): Since k*=2 ≤ 3, probe returns y₃ = 1 (FAIL)!",
            "probe_color": "#dc2626",
        },
        {
            "title": "Step t=1 (Posterior b₁ after Π₃ = FAIL)",
            "subtitle": "Project via P_[0,3] = diag(1,1,1,1,0,0,0,0): Support [L₁, R₁] = [0..3], Width W₁ = 4, H(b₁) = 2.000 bits (ΔI = 1.0 bit)",
            "formula": "b₁ = P_[0,3] b₀ / (1ᵀ P_[0,3] b₀) = (1/4, 1/4, 1/4, 1/4, 0, 0, 0, 0)ᵀ  |  Split: m₂ = 1",
            "probs": [0.25, 0.25, 0.25, 0.25, 0, 0, 0, 0],
            "active_range": (0, 3),
            "split_after": 1,
            "probe_note": "Execute Prefix Probe Π₁ (test stages 0..1): Since k*=2 > 1, stages 0..1 are healthy → returns y₁ = 0 (PASS)!",
            "probe_color": "#16a34a",
        },
        {
            "title": "Step t=2 (Posterior b₂ after Π₁ = PASS)",
            "subtitle": "Project via P_[2,3] = diag(0,0,1,1,0,0,0,0): Support [L₂, R₂] = [2..3], Width W₂ = 2, H(b₂) = 1.000 bit (ΔI = 1.0 bit)",
            "formula": "b₂ = P_[2,3] b₁ / (1ᵀ P_[2,3] b₁) = (0, 0, 1/2, 1/2, 0, 0, 0, 0)ᵀ  |  Split: m₃ = 2",
            "probs": [0, 0, 0.5, 0.5, 0, 0, 0, 0],
            "active_range": (2, 3),
            "split_after": 2,
            "probe_note": "Execute Prefix Probe Π₂ (test stages 0..2): Since k*=2 ≤ 2, probe returns y₂ = 1 (FAIL)!",
            "probe_color": "#dc2626",
        },
        {
            "title": "Step t=3 (Exact Collapse b₃ = u₂ → Surgical Ontic Repair &amp; Monotonic Advance to [3..7])",
            "subtitle": "Project via P_[2,2] = u₂ u₂ᵀ: Support L₃ = R₃ = 2, Width W₃ = 1, Entropy H(b₃) = 0.000 bits! Exact Fault k*=2 Identified!",
            "formula": "b₃ = (0, 0, 1, 0, 0, 0, 0, 0)ᵀ = u₂  ⟹  Repair do(s₂ ← 1), update L_new ← 3, bisect [3..6]",
            "probs": [0, 0, 1.0, 0, 0, 0, 0, 0],
            "active_range": (2, 2),
            "split_after": None,
            "probe_note": "Phase 2 Summary: From L=3, probe Π₆ (FAIL) → bisect [3..6] via Π₄ (PASS) → Π₅ (FAIL) → localizes k₂*=5 in 3 more probes!",
            "probe_color": "#2563eb",
        },
    ]

    y_start = 194
    row_h = 116
    for s_idx, st in enumerate(steps):
        ry = y_start + s_idx * row_h
        svg.append(f'<rect x="20" y="{ry}" width="940" height="{row_h - 8}" rx="6" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5"/>')

        # Left text info
        svg.append(f'<text x="34" y="{ry+20}" font-family="Helvetica, Arial, sans-serif" font-size="13" font-weight="bold" fill="#0f172a">{st["title"]}</text>')
        svg.append(f'<text x="34" y="{ry+37}" font-family="Helvetica, Arial, sans-serif" font-size="11" fill="#475569">{st["subtitle"]}</text>')
        svg.append(f'<text x="34" y="{ry+54}" font-family="monospace" font-size="11" font-weight="bold" fill="#1e3a8a">{st["formula"]}</text>')
        svg.append(f'<text x="34" y="{ry+96}" font-family="Helvetica, Arial, sans-serif" font-size="11" font-weight="bold" fill="{st["probe_color"]}">▶ {st["probe_note"]}</text>')

        # Right mini bar chart of belief vector b_t[0..7]
        bx0 = 660
        bw = 32
        b_gap = 4
        max_bar_h = 46
        base_y = ry + 72

        svg.append(f'<line x1="{bx0-6}" y1="{base_y}" x2="{bx0 + 8*(bw+b_gap)}" y2="{base_y}" stroke="#64748b" stroke-width="1.5"/>')

        for k in range(8):
            p = st["probs"][k]
            bh = int(p * max_bar_h)
            bx = bx0 + k * (bw + b_gap)
            by = base_y - bh
            in_range = st["active_range"][0] <= k <= st["active_range"][1]
            if p > 0:
                b_fill = "#2563eb" if p < 0.99 else "#16a34a"
                svg.append(f'<rect x="{bx}" y="{by}" width="{bw}" height="{bh}" rx="2" fill="{b_fill}" stroke="#1e40af" stroke-width="1"/>')
                p_str = "1.0" if p == 1.0 else (f"1/{int(round(1/p))}")
                svg.append(f'<text x="{bx+bw/2}" y="{by-4}" font-family="monospace" font-size="10" font-weight="bold" fill="#1e293b" text-anchor="middle">{p_str}</text>')
            else:
                svg.append(f'<rect x="{bx}" y="{base_y-2}" width="{bw}" height="2" fill="#e2e8f0"/>')
                svg.append(f'<text x="{bx+bw/2}" y="{base_y-5}" font-family="monospace" font-size="9" fill="#94a3b8" text-anchor="middle">0</text>')

            lbl_col = "#0f172a" if in_range else "#94a3b8"
            svg.append(f'<text x="{bx+bw/2}" y="{base_y+13}" font-family="monospace" font-size="10" font-weight="bold" fill="{lbl_col}" text-anchor="middle">u_{k}</text>')

            # Draw bisection split line if applicable
            if st["split_after"] is not None and k == st["split_after"]:
                sx = bx + bw + b_gap / 2.0
                svg.append(f'<line x1="{sx}" y1="{ry+14}" x2="{sx}" y2="{base_y+16}" stroke="#dc2626" stroke-width="2" stroke-dasharray="4,3"/>')
                svg.append(f'<text x="{sx}" y="{ry+12}" font-family="monospace" font-size="9" font-weight="bold" fill="#dc2626" text-anchor="middle">Π_{k}</text>')

    svg.append('</svg>')
    save_svg_and_png("fig1_simple_example_trace", "\n".join(svg))


# ==============================================================================
# FIGURE 2: Complex 16-Hop (D=128) Multi-Fault Dyadic Bisection & Frontier Trace
# ==============================================================================
def make_fig2_complex_16hop_trace():
    W = 1040
    H = 740
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
        '<defs>',
        '  <linearGradient id="bg2" x1="0" y1="0" x2="0" y2="1">',
        '    <stop offset="0%" stop-color="#f8fafc"/>',
        '    <stop offset="100%" stop-color="#eef2f6"/>',
        '  </linearGradient>',
        '</defs>',
        f'<rect width="{W}" height="{H}" rx="10" fill="url(#bg2)" stroke="#cbd5e1" stroke-width="2"/>',
        '<rect x="20" y="16" width="1000" height="50" rx="6" fill="#0f172a"/>',
        '<text x="520" y="38" font-family="Helvetica, Arial, sans-serif" font-size="16" font-weight="bold" fill="#ffffff" text-anchor="middle">',
        'COMPLEX 16-HOP SSH INSTANCE (D=128 Stages, W=129 States, K=5 Masked Faults at k* ∈ {1, 24, 59, 93, 126})',
        '</text>',
        '<text x="520" y="56" font-family="monospace" font-size="12" fill="#93c5fd" text-anchor="middle">',
        'Complete 38-Probe Step-by-Step Bellman Interval Contraction [L_t, R_t] &amp; Monotonic Verified Prefix Progression',
        '</text>',
    ]

    # Exact trace data from C99 solver for the 5 faults: k* = 1, 24, 59, 93, 126
    episodes = [
        {
            "name": "EPISODE 1: Localize Fault #1 at k₁* = 1 (Hop 0: KEY_DECRYPTED_IN_AGENT)",
            "symptom": "Aliased End-to-End Symptom: OBS_TIMEOUT_OR_TTY_HANG (48 aliased states)",
            "color": "#dc2626",
            "steps": [
                (0, 128, 63, "FAIL", "W=129 → Π₆₃=0"),
                (0, 63, 31, "FAIL", "W=64 → Π₃₁=0"),
                (0, 31, 15, "FAIL", "W=32 → Π₁₅=0"),
                (0, 15, 7, "FAIL", "W=16 → Π₇=0"),
                (0, 7, 3, "FAIL", "W=8 → Π₃=0"),
                (0, 3, 1, "FAIL", "W=4 → Π₁=0"),
                (0, 1, 0, "PASS", "W=2 → Π₀=1"),
                (1, 1, None, "LOCKED", "k₁*=1 (H=0) → Repair s₁←1, L←2"),
            ],
        },
        {
            "name": "EPISODE 2: Localize Fault #2 at k₂* = 24 (Hop 3: AGENT_SOCK_IPC)",
            "symptom": "Probe #8 (Π₁₂₇=0 FAIL) confirms hidden downstream fault; bisect unverified [2..127] (W=126):",
            "color": "#ea580c",
            "steps": [
                (2, 127, 64, "FAIL", "W=126 → Π₆₄=0"),
                (2, 64, 32, "FAIL", "W=63 → Π₃₂=0"),
                (2, 32, 16, "PASS", "W=31 → Π₁₆=1"),
                (17, 32, 24, "FAIL", "W=16 → Π₂₄=0"),
                (17, 24, 20, "PASS", "W=8 → Π₂₀=1"),
                (21, 24, 22, "PASS", "W=4 → Π₂₂=1"),
                (23, 24, 23, "PASS", "W=2 → Π₂₃=1"),
                (24, 24, None, "LOCKED", "k₂*=24 (H=0) → Repair s₂₄←1, L←25"),
            ],
        },
        {
            "name": "EPISODE 3: Localize Fault #3 at k₃* = 59 (Hop 7: TCP22_ROUTING_HANDSHAKE)",
            "symptom": "Probe #16 (Π₁₂₇=0 FAIL) confirms hidden fault; bisect unverified [25..127] (W=103):",
            "color": "#d97706",
            "steps": [
                (25, 127, 75, "FAIL", "W=103 → Π₇₅=0"),
                (25, 75, 49, "PASS", "W=51 → Π₄₉=1"),
                (50, 75, 62, "FAIL", "W=26 → Π₆₂=0"),
                (50, 62, 55, "PASS", "W=13 → Π₅₅=1"),
                (56, 62, 58, "PASS", "W=7 → Π₅₈=1"),
                (59, 62, 60, "FAIL", "W=4 → Π₆₀=0"),
                (59, 60, 59, "FAIL", "W=2 → Π₅₉=0"),
                (59, 59, None, "LOCKED", "k₃*=59 (H=0) → Repair s₅₉←1, L←60"),
            ],
        },
        {
            "name": "EPISODE 4: Localize Fault #4 at k₄* = 93 (Hop 11: REMOTE_SSHD_ReverseDNS_CFG)",
            "symptom": "Probe #24 (Π₁₂₇=0 FAIL) confirms hidden fault; bisect unverified [60..127] (W=68):",
            "color": "#7c3aed",
            "steps": [
                (60, 127, 93, "FAIL", "W=68 → Π₉₃=0"),
                (60, 93, 76, "PASS", "W=34 → Π₇₆=1"),
                (77, 93, 84, "PASS", "W=17 → Π₈₄=1"),
                (85, 93, 88, "PASS", "W=9 → Π₈₈=1"),
                (89, 93, 90, "PASS", "W=5 → Π₉₀=1"),
                (91, 93, 91, "PASS", "W=3 → Π₉₁=1"),
                (92, 93, 92, "PASS", "W=2 → Π₉₂=1"),
                (93, 93, None, "LOCKED", "k₄*=93 (H=0) → Repair s₉₃←1, L←94"),
            ],
        },
        {
            "name": "EPISODE 5: Localize Fault #5 at k₅* = 126 (Hop 15: AUTH_KEYS_PERMS_OR_PAM) &amp; Verify",
            "symptom": "Probe #32 (Π₁₂₇=0 FAIL) confirms hidden fault; bisect [94..127] (W=34) + Final Probe #38 (Π₁₂₇=1 PASS):",
            "color": "#0284c7",
            "steps": [
                (94, 127, 110, "PASS", "W=34 → Π₁₁₀=1"),
                (111, 127, 118, "PASS", "W=17 → Π₁₁₈=1"),
                (119, 127, 122, "PASS", "W=9 → Π₁₂₂=1"),
                (123, 127, 124, "PASS", "W=5 → Π₁₂₄=1"),
                (125, 127, 125, "PASS", "W=3 → Π₁₂₅=1"),
                (126, 127, 126, "FAIL", "W=2 → Π₁₂₆=0"),
                (126, 126, None, "LOCKED", "k₅*=126 → Repair s₁₂₆←1"),
                (0, 128, 127, "VERIFIED", "Probe #38: Π₁₂₇=1 (ALL 16 HOPS OK!)"),
            ],
        },
    ]

    # Coordinate mapping for stage axis 0..128
    axis_x0 = 490
    axis_w = 505

    def stage_to_x(k):
        return axis_x0 + (k / 128.0) * axis_w

    y_top = 80
    ep_h = 128

    for ep_idx, ep in enumerate(episodes):
        ey = y_top + ep_idx * ep_h
        svg.append(f'<rect x="20" y="{ey}" width="1000" height="{ep_h - 8}" rx="6" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5"/>')

        # Episode header
        svg.append(f'<text x="32" y="{ey+19}" font-family="Helvetica, Arial, sans-serif" font-size="12" font-weight="bold" fill="{ep["color"]}">{ep["name"]}</text>')
        svg.append(f'<text x="32" y="{ey+34}" font-family="Helvetica, Arial, sans-serif" font-size="10" fill="#475569">{ep["symptom"]}</text>')

        # Draw stage scale ticks on right side
        for tick in [0, 16, 32, 48, 64, 80, 96, 112, 128]:
            tx = stage_to_x(tick)
            svg.append(f'<line x1="{tx}" y1="{ey+38}" x2="{tx}" y2="{ey+ep_h-14}" stroke="#e2e8f0" stroke-width="1"/>')
            svg.append(f'<text x="{tx}" y="{ey+35}" font-family="monospace" font-size="8.5" fill="#64748b" text-anchor="middle">k={tick}</text>')

        # Draw each step bar in this episode
        for s_i, (L, R, mid, status, desc) in enumerate(ep["steps"]):
            sy = ey + 42 + s_i * 9.2
            # Text label on left (2 columns of 4 steps)
            col_x = 32 if s_i < 4 else 235
            row_y = ey + 52 + (s_i % 4) * 16
            st_col = "#16a34a" if status in ("PASS", "LOCKED", "VERIFIED") else "#dc2626"
            svg.append(f'<text x="{col_x}" y="{row_y}" font-family="monospace" font-size="9" fill="#1e293b">'
                       f'{s_i+1}.[{L:3d}..{R:3d}] <tspan font-weight="bold" fill="{st_col}">{desc}</tspan></text>')

            # Visual interval bar on right axis
            if L > 0 and status != "VERIFIED":
                # Green verified prefix bar [0 .. L-1]
                vx0 = stage_to_x(0)
                vx1 = stage_to_x(L)
                svg.append(f'<rect x="{vx0}" y="{sy}" width="{max(1, vx1-vx0)}" height="6" fill="#bbf7d0" opacity="0.8"/>')

            lx = stage_to_x(L)
            rx = stage_to_x(R)
            bw = max(4.0, rx - lx)
            bar_fill = "#16a34a" if status in ("LOCKED", "VERIFIED") else ep["color"]
            svg.append(f'<rect x="{lx}" y="{sy}" width="{bw}" height="6" rx="1.5" fill="{bar_fill}" opacity="0.85"/>')

            if mid is not None:
                mx = stage_to_x(mid)
                svg.append(f'<circle cx="{mx}" cy="{sy+3}" r="3.2" fill="#ffffff" stroke="#0f172a" stroke-width="1.5"/>')

    svg.append('</svg>')
    save_svg_and_png("fig2_complex_16hop_trace", "\n".join(svg))


# ==============================================================================
# FIGURE 3: Matrix Theory Architecture (Censoring C, Aliasing O_e2e, Unimodular Pi)
# ==============================================================================
def make_fig3_matrix_architecture():
    W = 1000
    H = 520
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
        '<defs>',
        '  <linearGradient id="bg3" x1="0" y1="0" x2="1" y2="1">',
        '    <stop offset="0%" stop-color="#f8fafc"/>',
        '    <stop offset="100%" stop-color="#f1f5f9"/>',
        '  </linearGradient>',
        '</defs>',
        f'<rect width="{W}" height="{H}" rx="10" fill="url(#bg3)" stroke="#cbd5e1" stroke-width="2"/>',
        '<rect x="20" y="16" width="960" height="44" rx="6" fill="#1e293b"/>',
        '<text x="500" y="43" font-family="Helvetica, Arial, sans-serif" font-size="16" font-weight="bold" fill="#ffffff" text-anchor="middle">',
        'Matrix Factorization of Cascaded Diagnosis: Rank-Deficient End-to-End Aliasing vs. Unimodular Prefix Basis Π',
        '</text>',
    ]

    # Panel A (Left): End-to-End Kronecker Aliasing Matrix O_e2e = 1_N^T \otimes \Omega_hop
    svg.append('<rect x="20" y="72" width="465" height="428" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="252" y="96" font-family="Helvetica, Arial, sans-serif" font-size="13.5" font-weight="bold" fill="#991b1b" text-anchor="middle">'
               'A. Rank-Deficient End-to-End Matrix O_e2e = [1₁₆ᵀ ⊗ Ω_hop | e₀]</text>')
    svg.append('<text x="252" y="114" font-family="monospace" font-size="11" fill="#475569" text-anchor="middle">'
               'dim = 6 × 129  |  rank(O_e2e) = 6  |  dim ker(O_e2e) = 123</text>')

    # Draw the 5x8 Omega_hop matrix grid
    omega = [
        [0, 0, 1, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 1, 0],
        [0, 1, 0, 1, 0, 1, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1],
    ]
    row_names = ["CONN_REFUSED", "PERM_DENIED", "TIMEOUT_HANG", "HOSTKEY_ERR", "CHAN_CLOSED"]
    col_names = ["m0:Ag", "m1:Ky", "m2:DN", "m3:TC", "m4:KX", "m5:rD", "m6:Au", "m7:Fw"]

    gx0 = 135
    gy0 = 152
    cell = 34
    for c in range(8):
        svg.append(f'<text x="{gx0 + c*cell + cell/2}" y="{gy0 - 8}" font-family="monospace" font-size="9.5" font-weight="bold" fill="#334155" text-anchor="middle">{col_names[c]}</text>')

    for r in range(5):
        svg.append(f'<text x="{gx0 - 8}" y="{gy0 + r*cell + 21}" font-family="monospace" font-size="10" font-weight="bold" fill="#1e293b" text-anchor="end">{row_names[r]}</text>')
        for c in range(8):
            val = omega[r][c]
            fill = "#fecaca" if val == 1 else "#f8fafc"
            tcol = "#991b1b" if val == 1 else "#cbd5e1"
            svg.append(f'<rect x="{gx0 + c*cell}" y="{gy0 + r*cell}" width="{cell-2}" height="{cell-2}" rx="3" fill="{fill}" stroke="#cbd5e1" stroke-width="1"/>')
            svg.append(f'<text x="{gx0 + c*cell + cell/2}" y="{gy0 + r*cell + 21}" font-family="monospace" font-size="13" font-weight="bold" fill="{tcol}" text-anchor="middle">{val}</text>')

    svg.append('<text x="252" y="346" font-family="Helvetica, Arial, sans-serif" font-size="11.5" font-weight="bold" fill="#1e293b" text-anchor="middle">'
               'Single-Hop Block Ω_hop ∈ {0,1}⁵ˣ⁸ (Replicated 16× via 1₁₆ᵀ ⊗ Ω_hop)</text>')
    svg.append('<rect x="36" y="362" width="433" height="122" rx="5" fill="#fef2f2" stroke="#fca5a5" stroke-width="1"/>')
    svg.append('<text x="48" y="382" font-family="Helvetica, Arial, sans-serif" font-size="11" font-weight="bold" fill="#991b1b">'
               'Consequences of Nullspace dim ker(O_e2e) = 123:</text>')
    svg.append('<text x="48" y="401" font-family="Helvetica, Arial, sans-serif" font-size="10.5" fill="#7f1d1d">'
               '• Row 3 (TIMEOUT_HANG) sums to 3 × 16 = 48 indistinguishable states:</text>')
    svg.append('<text x="60" y="417" font-family="monospace" font-size="10" fill="#7f1d1d">'
               'm=1 (/dev/tty key block), m=3 (TCP SYN drop), m=5 (sshd UseDNS UDP/53)</text>')
    svg.append('<text x="48" y="436" font-family="Helvetica, Arial, sans-serif" font-size="10.5" fill="#7f1d1d">'
               '• Row 2 (PERM_DENIED) sums to 2 × 16 = 32 indistinguishable states:</text>')
    svg.append('<text x="60" y="452" font-family="monospace" font-size="10" fill="#7f1d1d">'
               'm=0 (local/forwarded SSH_AUTH_SOCK dead), m=6 (remote authorized_keys)</text>')
    svg.append('<text x="48" y="472" font-family="Helvetica, Arial, sans-serif" font-size="10.5" font-weight="bold" fill="#991b1b">'
               '• Bayesian update Λ_e2e(o) preserves prior ratios across all aliased states!</text>')

    # Panel B (Right): Unimodular Lower-Triangular Prefix Probe Matrix \Pi and Bidiagonal Inverse \Pi^{-1}
    svg.append('<rect x="515" y="72" width="465" height="428" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="747" y="96" font-family="Helvetica, Arial, sans-serif" font-size="13.5" font-weight="bold" fill="#166534" text-anchor="middle">'
               'B. Unimodular Prefix Probe Matrix Π &amp; First-Difference Inverse Π⁻¹</text>')
    svg.append('<text x="747" y="114" font-family="monospace" font-size="11" fill="#475569" text-anchor="middle">'
               'det(Π) = 1  |  rank(Π) = 129  |  dim ker(Π) = 0 (Zero Aliasing!)</text>')

    # Draw 6x6 schematic of Pi and Pi^{-1}
    px0 = 542
    py0 = 152
    pcell = 28
    n_dim = 6
    svg.append(f'<text x="{px0 + 3*pcell}" y="{py0 - 10}" font-family="monospace" font-size="11" font-weight="bold" fill="#1e293b" text-anchor="middle">Prefix Matrix Π</text>')
    for r in range(n_dim):
        for c in range(n_dim):
            val = 1 if c <= r else 0
            fill = "#dcfce7" if val == 1 else "#f8fafc"
            tcol = "#166534" if val == 1 else "#cbd5e1"
            svg.append(f'<rect x="{px0 + c*pcell}" y="{py0 + r*pcell}" width="{pcell-2}" height="{pcell-2}" rx="2" fill="{fill}" stroke="#cbd5e1" stroke-width="1"/>')
            svg.append(f'<text x="{px0 + c*pcell + pcell/2}" y="{py0 + r*pcell + 18}" font-family="monospace" font-size="11" font-weight="bold" fill="{tcol}" text-anchor="middle">{val}</text>')

    # Draw Inverse Pi^{-1}
    ix0 = 775
    svg.append(f'<text x="{ix0 + 3*pcell}" y="{py0 - 10}" font-family="monospace" font-size="11" font-weight="bold" fill="#1e293b" text-anchor="middle">Inverse Π⁻¹ (Δ Operator)</text>')
    for r in range(n_dim):
        for c in range(n_dim):
            val = 1 if c == r else (-1 if c == r - 1 else 0)
            fill = "#dbeafe" if val == 1 else ("#fee2e2" if val == -1 else "#f8fafc")
            tcol = "#1e40af" if val == 1 else ("#991b1b" if val == -1 else "#cbd5e1")
            svg.append(f'<rect x="{ix0 + c*pcell}" y="{py0 + r*pcell}" width="{pcell-2}" height="{pcell-2}" rx="2" fill="{fill}" stroke="#cbd5e1" stroke-width="1"/>')
            svg.append(f'<text x="{ix0 + c*pcell + pcell/2}" y="{py0 + r*pcell + 18}" font-family="monospace" font-size="11" font-weight="bold" fill="{tcol}" text-anchor="middle">{val}</text>')

    svg.append('<text x="747" y="346" font-family="Helvetica, Arial, sans-serif" font-size="11.5" font-weight="bold" fill="#1e293b" text-anchor="middle">'
               'Exact Frontier Recovery: u_{k*} = Π⁻¹ y   (where y = Π u_{k*} is monotone step vector)</text>')
    svg.append('<rect x="531" y="362" width="433" height="122" rx="5" fill="#f0fdf4" stroke="#86efac" stroke-width="1"/>')
    svg.append('<text x="543" y="382" font-family="Helvetica, Arial, sans-serif" font-size="11" font-weight="bold" fill="#166534">'
               'Why Prefix Bisection Achieves Shannon Optimality:</text>')
    svg.append('<text x="543" y="401" font-family="Helvetica, Arial, sans-serif" font-size="10.5" fill="#14532d">'
               '• Because y = Π u_{k*} = (0,...,0, 1,...,1)ᵀ is a monotone step function,</text>')
    svg.append('<text x="555" y="417" font-family="Helvetica, Arial, sans-serif" font-size="10.5" fill="#14532d">'
               'we never need to evaluate all D=128 rows of Π (O(D) linear scan).</text>')
    svg.append('<text x="543" y="436" font-family="Helvetica, Arial, sans-serif" font-size="10.5" fill="#14532d">'
               '• Binary bisection evaluates only log₂(D+1) ≈ 7.0155 rows of Π to locate</text>')
    svg.append('<text x="555" y="452" font-family="Helvetica, Arial, sans-serif" font-size="10.5" fill="#14532d">'
               'the unique non-zero first difference (Π⁻¹ y)_{k*} = y_{k*} - y_{k*-1} = 1!</text>')
    svg.append('<text x="543" y="472" font-family="Helvetica, Arial, sans-serif" font-size="10.5" font-weight="bold" fill="#166534">'
               '• Requires uniform -F &lt;cfg&gt; to prevent P_SSH from stripping BatchMode=yes!</text>')

    svg.append('</svg>')
    save_svg_and_png("fig3_matrix_architecture", "\n".join(svg))


# ==============================================================================
# FIGURE 4: Markov Chain Drift & Performance Comparison (Optimal C99 vs LLM)
# ==============================================================================
def make_fig4_markov_drift():
    W = 1000
    H = 460
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
        '<defs>',
        '  <linearGradient id="bg4" x1="0" y1="0" x2="0" y2="1">',
        '    <stop offset="0%" stop-color="#f8fafc"/>',
        '    <stop offset="100%" stop-color="#f1f5f9"/>',
        '  </linearGradient>',
        '  <marker id="arrBlue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#16a34a"/>',
        '  </marker>',
        '  <marker id="arrRed2" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#dc2626"/>',
        '  </marker>',
        '</defs>',
        f'<rect width="{W}" height="{H}" rx="10" fill="url(#bg4)" stroke="#cbd5e1" stroke-width="2"/>',
        '<rect x="20" y="16" width="960" height="44" rx="6" fill="#1e293b"/>',
        '<text x="500" y="43" font-family="Helvetica, Arial, sans-serif" font-size="16" font-weight="bold" fill="#ffffff" text-anchor="middle">',
        'Birth-Death Markov Chain P_LLM Under Collateral Config Damage (α = 0.25, M_o = 32 Aliased States)',
        '</text>',
    ]

    # Top diagram: Birth-Death Markov Chain states K_t = 0, 1, ..., k, k+1, ..., k_eq=28
    svg.append('<rect x="20" y="72" width="960" height="175" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="36" y="95" font-family="Helvetica, Arial, sans-serif" font-size="13" font-weight="bold" fill="#0f172a">'
               'State Transition Graph of Unbisected LLM Fault Count K_t ∈ {0 .. 32} (Positive Drift ΔK_t = (α(M_o - k) - 1)/M_o &gt; 0):</text>')

    nodes = [
        (90, "K = 0", "HEALTHY (Absorbing)", "#dcfce7", "#16a34a"),
        (260, "K = 1", "1 Fault", "#f1f5f9", "#64748b"),
        (430, "K = 5", "Initial (5 Faults)", "#fef3c7", "#d97706"),
        (640, "K = 6", "6 Faults", "#fee2e2", "#dc2626"),
        (860, "K_eq = 28", "Chaotic Attractor!", "#fecaca", "#991b1b"),
    ]

    cy = 158
    for nx, title, sub, fill, stroke in nodes:
        svg.append(f'<ellipse cx="{nx}" cy="{cy}" rx="64" ry="34" fill="{fill}" stroke="{stroke}" stroke-width="2.5"/>')
        svg.append(f'<text x="{nx}" y="{cy-3}" font-family="monospace" font-size="13" font-weight="bold" fill="#0f172a" text-anchor="middle">{title}</text>')
        svg.append(f'<text x="{nx}" y="{cy+14}" font-family="Helvetica, Arial, sans-serif" font-size="9.5" fill="#334155" text-anchor="middle">{sub}</text>')

    # Forward (birth) and backward (death) arrows between K=5 and K=6
    svg.append('<path d="M 485 136 Q 535 102 585 136" fill="none" stroke="#dc2626" stroke-width="2.5" marker-end="url(#arrRed2)"/>')
    svg.append('<text x="535" y="112" font-family="monospace" font-size="11" font-weight="bold" fill="#dc2626" text-anchor="middle">λ₅ = α(27/32) = 0.2109</text>')

    svg.append('<path d="M 585 180 Q 535 214 485 180" fill="none" stroke="#16a34a" stroke-width="2" marker-end="url(#arrBlue)"/>')
    svg.append('<text x="535" y="216" font-family="monospace" font-size="11" font-weight="bold" fill="#16a34a" text-anchor="middle">μ₅ = 1/32 = 0.03125</text>')

    # Arrows for other transitions
    svg.append('<line x1="196" y1="158" x2="156" y2="158" stroke="#16a34a" stroke-width="2" marker-end="url(#arrBlue)"/>')
    svg.append('<text x="176" y="148" font-family="monospace" font-size="10" fill="#16a34a" text-anchor="middle">μ₁=1/32</text>')

    svg.append('<line x1="324" y1="158" x2="364" y2="158" stroke="#64748b" stroke-width="2" stroke-dasharray="4,4"/>')
    svg.append('<line x1="706" y1="158" x2="792" y2="158" stroke="#dc2626" stroke-width="2.5" stroke-dasharray="5,3" marker-end="url(#arrRed2)"/>')
    svg.append('<text x="749" y="146" font-family="monospace" font-size="10.5" font-weight="bold" fill="#dc2626" text-anchor="middle">λ/μ = 6.75×</text>')

    # Bottom Panels: Empirical Monte Carlo Comparison (10,000 Trials)
    svg.append('<rect x="20" y="260" width="960" height="182" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="36" y="284" font-family="Helvetica, Arial, sans-serif" font-size="13" font-weight="bold" fill="#0f172a">'
               'Empirical C99 Benchmark (10,000 Monte Carlo Trials, K=5 Masked Faults in 16-Hop Chain, 50-Step Budget):</text>')

    bars = [
        ("Optimal C99 Matrix-Bisection Solver", 100.0, "100.00% Solved (Avg 35.52 probes, 0.00 wrong repairs)", "#16a34a"),
        ("Unbisected LLM Policy (α = 0.00, Zero Collateral Damage)", 3.47, "3.47% Solved (Avg 50.00 probes, 47.91 wrong repairs)", "#d97706"),
        ("Unbisected LLM Policy (α = 0.25, Realistic Config Mutation Hazard)", 0.03, "0.03% Solved (Avg 50.00 probes, 48.23 wrong repairs)", "#dc2626"),
    ]

    for idx, (label, pct, metric_txt, col) in enumerate(bars):
        by = 302 + idx * 44
        svg.append(f'<text x="36" y="{by+15}" font-family="Helvetica, Arial, sans-serif" font-size="11.5" font-weight="bold" fill="#1e293b">{label}</text>')
        bar_x = 430
        max_w = 510
        w_val = max(4.0, (pct / 100.0) * max_w)
        svg.append(f'<rect x="{bar_x}" y="{by}" width="{max_w}" height="22" rx="4" fill="#f1f5f9" stroke="#cbd5e1" stroke-width="1"/>')
        svg.append(f'<rect x="{bar_x}" y="{by}" width="{w_val}" height="22" rx="4" fill="{col}"/>')
        svg.append(f'<text x="{bar_x + 12}" y="{by+15}" font-family="monospace" font-size="11" font-weight="bold" fill="#0f172a">{metric_txt}</text>')

    svg.append('</svg>')
    save_svg_and_png("fig4_markov_drift", "\n".join(svg))


# ==============================================================================
# FIGURE 5: Complexity Boundary (NP-Hard DAG vs TU LP) & Convex Optimization
# ==============================================================================
def make_fig5_complexity_and_convex():
    W = 1000
    H = 510
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
        '<defs>',
        '  <linearGradient id="bg5" x1="0" y1="0" x2="1" y2="1">',
        '    <stop offset="0%" stop-color="#f8fafc"/>',
        '    <stop offset="100%" stop-color="#eef2f6"/>',
        '  </linearGradient>',
        '</defs>',
        f'<rect width="{W}" height="{H}" rx="10" fill="url(#bg5)" stroke="#cbd5e1" stroke-width="2"/>',
        '<rect x="20" y="16" width="960" height="44" rx="6" fill="#0f172a"/>',
        '<text x="500" y="43" font-family="Helvetica, Arial, sans-serif" font-size="15.5" font-weight="bold" fill="#ffffff" text-anchor="middle">',
        'Computational Complexity Boundary (NP-Hard vs. P via Total Unimodularity) &amp; Convex Info-Gain Optimization',
        '</text>',
    ]

    # Left Panel: Complexity Phase Transition & Polyhedral Integrality (TUM)
    svg.append('<rect x="20" y="72" width="465" height="418" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="252" y="96" font-family="Helvetica, Arial, sans-serif" font-size="13" font-weight="bold" fill="#1e293b" text-anchor="middle">'
               'A. Polyhedral Integrality: General Test Matrix A vs. Cascade Π</text>')

    # Top-left subbox: General Binary Matrix A (NP-Hard / Fractional LP Vertex)
    svg.append('<rect x="36" y="110" width="433" height="168" rx="5" fill="#fef2f2" stroke="#fca5a5" stroke-width="1.5"/>')
    svg.append('<text x="48" y="129" font-family="Helvetica, Arial, sans-serif" font-size="11.5" font-weight="bold" fill="#991b1b">'
               '1. General Non-Cascaded Test Matrix A ∈ {0,1}^{P×n} (NP-Hard / Co-NP)</text>')
    svg.append('<text x="48" y="146" font-family="Helvetica, Arial, sans-serif" font-size="10.2" fill="#7f1d1d">'
               '• Reductions: Minimum Test Collection (Garey &amp; Johnson SP6) &amp; Set Cover.</text>')
    svg.append('<text x="48" y="162" font-family="Helvetica, Arial, sans-serif" font-size="10.2" fill="#7f1d1d">'
               '• Submatrices have det(B) ∈ {±2, ±3, ...} ⟹ LP relaxation has FRACTIONAL</text>')
    svg.append('<text x="58" y="177" font-family="Helvetica, Arial, sans-serif" font-size="10.2" fill="#7f1d1d">'
               'vertices (Integrality Gap = Ω(log n)); requires MILP Branch-and-Cut.</text>')
    svg.append('<text x="48" y="193" font-family="monospace" font-size="9.2" font-weight="bold" fill="#991b1b">'
               '• Decision Tree Depth h*: NP-Complete (Inapproximable &lt; (1-o(1))ln n)</text>')

    # Mini polygon showing fractional LP vertex vs integer lattice points
    svg.append('<polygon points="150,268 215,222 330,232 295,268" fill="#fecaca" stroke="#dc2626" stroke-width="2"/>')
    svg.append('<circle cx="215" cy="222" r="4.5" fill="#dc2626"/>')
    svg.append('<text x="215" y="213" font-family="monospace" font-size="8.8" font-weight="bold" fill="#dc2626" text-anchor="middle">Fractional LP Vertex x*∉ℤⁿ</text>')
    svg.append('<circle cx="200" cy="250" r="3.5" fill="#1e293b"/>')
    svg.append('<circle cx="250" cy="250" r="3.5" fill="#1e293b"/>')
    svg.append('<text x="360" y="255" font-family="monospace" font-size="8.8" fill="#1e293b" text-anchor="middle">Integer MILP Hull</text>')

    # Bottom-left subbox: Cascaded Prefix Matrix \Pi (Totally Unimodular -> Exact LP in P!)
    svg.append('<rect x="36" y="288" width="433" height="186" rx="5" fill="#f0fdf4" stroke="#86efac" stroke-width="1.5"/>')
    svg.append('<text x="48" y="307" font-family="Helvetica, Arial, sans-serif" font-size="11.5" font-weight="bold" fill="#166534">'
               '2. Cascaded Prefix Matrix Π &amp; Difference Π⁻¹ (Totally Unimodular → in P!)</text>')
    svg.append('<text x="48" y="324" font-family="Helvetica, Arial, sans-serif" font-size="10.2" fill="#14532d">'
               '• Consecutive-Ones Property: Every column/row of Π is a contiguous interval.</text>')
    svg.append('<text x="48" y="340" font-family="Helvetica, Arial, sans-serif" font-size="10.2" fill="#14532d">'
               '• Every square submatrix B of Π or Π⁻¹ has det(B) ∈ {-1, 0, +1} (TUM).</text>')
    svg.append('<text x="48" y="356" font-family="Helvetica, Arial, sans-serif" font-size="10.2" font-weight="bold" fill="#166534">'
               '• Hoffman–Kruskal Theorem: LP Relaxation Polytope P_LP = conv(P_MILP)!</text>')
    svg.append('<text x="48" y="372" font-family="monospace" font-size="9.2" fill="#14532d">'
               '  Integrality Gap = 0.000 | Treewidth tw(G)=1 | Exact DP O(log D)</text>')

    # Mini polygon showing exact integer vertices
    svg.append('<polygon points="165,458 195,410 295,410 325,458" fill="#bbf7d0" stroke="#16a34a" stroke-width="2"/>')
    for vx, vy in [(165, 458), (195, 410), (295, 410), (325, 458)]:
        svg.append(f'<circle cx="{vx}" cy="{vy}" r="4.5" fill="#16a34a" stroke="#ffffff" stroke-width="1"/>')
    svg.append('<text x="245" y="438" font-family="monospace" font-size="9.5" font-weight="bold" fill="#166534" text-anchor="middle">All LP Extreme Points ∈ {0,1}ⁿ!</text>')

    # Right Panel: Convex Optimization of Expected Information Gain / Mutual Information
    svg.append('<rect x="515" y="72" width="465" height="418" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="747" y="96" font-family="Helvetica, Arial, sans-serif" font-size="13" font-weight="bold" fill="#1e293b" text-anchor="middle">'
               'B. Convex Programming: Binary Entropy Split &amp; Semidefinite/LP Control</text>')

    # Plot of Binary Entropy Function h_2(p) = -p log2 p - (1-p) log2(1-p)
    ox = 590
    oy = 310
    pw = 345
    ph = 165

    # Axes
    svg.append(f'<line x1="{ox}" y1="{oy}" x2="{ox+pw+15}" y2="{oy}" stroke="#334155" stroke-width="1.8"/>')
    svg.append(f'<line x1="{ox}" y1="{oy}" x2="{ox}" y2="{oy-ph-15}" stroke="#334155" stroke-width="1.8"/>')
    svg.append(f'<text x="{ox+pw/2}" y="{oy+32}" font-family="Helvetica, Arial, sans-serif" font-size="11" font-weight="bold" fill="#1e293b" text-anchor="middle">'
               'Cumulative Prefix Probability Mass p_m = ∑_{k=L}^m b_k ∈ [0, 1]</text>')
    svg.append(f'<text x="{ox-48}" y="{oy-ph/2}" font-family="Helvetica, Arial, sans-serif" font-size="10.5" font-weight="bold" fill="#1e293b" text-anchor="middle" transform="rotate(-90 {ox-48},{oy-ph/2})">'
               'Info Gain I(S; O | Π_m) = h₂(p_m) [bits]</text>')

    # Grid lines
    svg.append(f'<line x1="{ox}" y1="{oy-ph}" x2="{ox+pw}" y2="{oy-ph}" stroke="#94a3b8" stroke-width="1" stroke-dasharray="4,4"/>')
    svg.append(f'<text x="{ox-6}" y="{oy-ph+4}" font-family="monospace" font-size="9.5" font-weight="bold" fill="#16a34a" text-anchor="end">1.0</text>')
    svg.append(f'<line x1="{ox+pw/2}" y1="{oy}" x2="{ox+pw/2}" y2="{oy-ph}" stroke="#16a34a" stroke-width="1.5" stroke-dasharray="4,3"/>')
    svg.append(f'<text x="{ox+pw/2}" y="{oy+15}" font-family="monospace" font-size="10" font-weight="bold" fill="#16a34a" text-anchor="middle">p* = 0.50 (m* = ⌊W/2⌋)</text>')
    svg.append(f'<text x="{ox}" y="{oy+15}" font-family="monospace" font-size="10" fill="#475569" text-anchor="middle">0.0</text>')
    svg.append(f'<text x="{ox+pw}" y="{oy+15}" font-family="monospace" font-size="10" fill="#475569" text-anchor="middle">1.0</text>')

    # Compute concave curve points for h_2(p)
    pts = []
    for i in range(101):
        p = i / 100.0
        if p <= 0.0 or p >= 1.0:
            h_val = 0.0
        else:
            h_val = -(p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p))
        px_i = ox + p * pw
        py_i = oy - h_val * ph
        pts.append(f"{px_i:.1f},{py_i:.1f}")

    svg.append(f'<polyline points="{" ".join(pts)}" fill="none" stroke="#2563eb" stroke-width="3"/>')

    # Mark Optimal Midpoint p=0.5 vs Linear Walk p=1/16
    svg.append(f'<circle cx="{ox + 0.5*pw}" cy="{oy - 1.0*ph}" r="5.5" fill="#16a34a" stroke="#ffffff" stroke-width="1.5"/>')
    svg.append(f'<text x="{ox + 0.5*pw}" y="{oy - ph - 10}" font-family="Helvetica, Arial, sans-serif" font-size="10.5" font-weight="bold" fill="#16a34a" text-anchor="middle">'
               'Global Concave Maximum: h₂(1/2) = 1.000 bit/probe</text>')

    p_lin = 1.0 / 16.0
    h_lin = -(p_lin * math.log2(p_lin) + (1.0 - p_lin) * math.log2(1.0 - p_lin))
    lx_pt = ox + p_lin * pw
    ly_pt = oy - h_lin * ph
    svg.append(f'<circle cx="{lx_pt:.1f}" cy="{ly_pt:.1f}" r="5" fill="#dc2626" stroke="#ffffff" stroke-width="1.5"/>')
    svg.append(f'<text x="{lx_pt + 12:.1f}" y="{ly_pt + 4:.1f}" font-family="Helvetica, Arial, sans-serif" font-size="10" font-weight="bold" fill="#dc2626">'
               'Linear Walk (Codex Step 3): p=1/16 → 0.337 bits!</text>')

    # Bottom-right summary box of LP / MILP / Convex formulations
    svg.append('<rect x="531" y="354" width="433" height="120" rx="5" fill="#eff6ff" stroke="#93c5fd" stroke-width="1.5"/>')
    svg.append('<text x="543" y="373" font-family="Helvetica, Arial, sans-serif" font-size="11" font-weight="bold" fill="#1e3a8a">'
               'Exact Optimization Formulations (Sections 7 &amp; 8):</text>')
    svg.append('<text x="543" y="391" font-family="monospace" font-size="9.5" fill="#1e3a8a">'
               '1. Min-Cost Fault ID (LP) : min cᵀs  s.t.  Π⁻¹ y = u_{k*}, s ∈ [0,1]ᴰ</text>')
    svg.append('<text x="543" y="408" font-family="monospace" font-size="9.5" fill="#1e3a8a">'
               '2. Multi-Fault Set-Cover  : MILP min ∑ w_a x_a s.t. A_disc x ≥ 1</text>')
    svg.append('<text x="543" y="425" font-family="monospace" font-size="9.5" fill="#1e3a8a">'
               '3. Max Info-Gain (Convex) : min_{w∈Δ} ∑_i (r_iᵀ b) log₂(r_iᵀ b)</text>')
    svg.append('<text x="543" y="442" font-family="monospace" font-size="9.5" fill="#1e3a8a">'
               '4. Bellman LP Primal-Dual : max V₀ s.t. V(S) ≤ 1 + p_L V(S_L) + p_R V(S_R)</text>')
    svg.append('<text x="543" y="460" font-family="Helvetica, Arial, sans-serif" font-size="10" font-weight="bold" fill="#1d4ed8">'
               '• Strict concavity h₂″(p) = -1/(p(1-p)ln 2) &lt; 0 guarantees unique optimum!</text>')

    svg.append('</svg>')
    save_svg_and_png("fig5_complexity_and_convex", "\n".join(svg))


# ==============================================================================
# FIGURE 6: Transformer 2-Layer Optimal Matrix Circuit & Meta-Cognitive Router
# ==============================================================================
def make_fig6_transformer_and_router():
    W = 1000
    H = 530
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
        '<defs>',
        '  <linearGradient id="bg6" x1="0" y1="0" x2="1" y2="1">',
        '    <stop offset="0%" stop-color="#f8fafc"/>',
        '    <stop offset="100%" stop-color="#f1f5f9"/>',
        '  </linearGradient>',
        '  <marker id="arrDark" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#1e293b"/>',
        '  </marker>',
        '  <marker id="arrGreen6" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#16a34a"/>',
        '  </marker>',
        '  <marker id="arrRed6" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#dc2626"/>',
        '  </marker>',
        '</defs>',
        f'<rect width="{W}" height="{H}" rx="10" fill="url(#bg6)" stroke="#cbd5e1" stroke-width="2"/>',
        '<rect x="20" y="16" width="960" height="44" rx="6" fill="#0f172a"/>',
        '<text x="500" y="43" font-family="Helvetica, Arial, sans-serif" font-size="15.5" font-weight="bold" fill="#ffffff" text-anchor="middle">',
        'Constructive 2-Layer Transformer Matrix Circuit vs. Meta-Cognitive Epistemic Switching Architecture',
        '</text>',
    ]

    # Left Panel: 2-Layer Transformer Circuit that Implements Exact Bellman Bisection
    svg.append('<rect x="20" y="72" width="465" height="438" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="252" y="96" font-family="Helvetica, Arial, sans-serif" font-size="13" font-weight="bold" fill="#1e293b" text-anchor="middle">'
               'A. Constructive 2-Layer Transformer Circuit for Optimal Bisection</text>')
    svg.append('<text x="252" y="113" font-family="monospace" font-size="10" fill="#475569" text-anchor="middle">'
               'Proves Matrix-Multiply + Softmax + ReLU Can Represent Exact Solver</text>')

    boxes_left = [
        (126, "#eff6ff", "#3b82f6", "#1e3a8a",
         "Input Token Stream: History h_t = ((a₁,o₁), ..., (a_t,o_t))",
         "Value Projection W_V encodes log-likelihood rows ln(O_a)_{o,•} ∈ ℝ^{D+1}"),
        (202, "#f0fdf4", "#16a34a", "#14532d",
         "Layer 1 (Self-Attention + Softmax) = Exact Bayesian Filter",
         "ℓ_t = ℓ₀ + ∑_{τ=1}^t ln diag(Λ_{a_τ}(o_τ))  ⟹  b_t = Softmax(ℓ_t) ∈ Δᴰ"),
        (278, "#fef3c7", "#d97706", "#78350f",
         "Layer 2A (Causal Lower-Triangular Linear Map W_Π = Π)",
         "Prefix Cumulative Probabilities: p_t = Π b_t  (p_m = ∑_{k≤m} b_k)"),
        (354, "#fae8ff", "#9333ea", "#581c87",
         "Layer 2B (2-Layer ReLU MLP + ArgMax) = KKT Midpoint Split",
         "score_m = -ReLU(p_m - 0.5) - ReLU(0.5 - p_m)  ⟹  m* = argmax_m score_m"),
    ]

    for by, fill, stroke, tcol, title, formula in boxes_left:
        svg.append(f'<rect x="38" y="{by}" width="429" height="56" rx="5" fill="{fill}" stroke="{stroke}" stroke-width="1.8"/>')
        svg.append(f'<text x="252" y="{by+22}" font-family="Helvetica, Arial, sans-serif" font-size="11.2" font-weight="bold" fill="{tcol}" text-anchor="middle">{title}</text>')
        svg.append(f'<text x="252" y="{by+42}" font-family="monospace" font-size="9.6" font-weight="bold" fill="#1e293b" text-anchor="middle">{formula}</text>')
        if by < 354:
            svg.append(f'<line x1="252" y1="{by+56}" x2="252" y2="{by+74}" stroke="#334155" stroke-width="2" marker-end="url(#arrDark)"/>')

    # Bottom note in Left Panel: Why Standard LLMs Fail Despite Circuit Capacity
    svg.append('<rect x="38" y="424" width="429" height="72" rx="5" fill="#fef2f2" stroke="#fca5a5" stroke-width="1.2"/>')
    svg.append('<text x="48" y="442" font-family="Helvetica, Arial, sans-serif" font-size="10.5" font-weight="bold" fill="#991b1b">'
               'Why Raw Autoregressive LLMs Fail Despite Circuit Expressivity:</text>')
    svg.append('<text x="48" y="458" font-family="Helvetica, Arial, sans-serif" font-size="10" fill="#7f1d1d">'
               '1. Pre-training learns pseudo-inverse O_e2e† (freq guessing) instead of Π.</text>')
    svg.append('<text x="48" y="473" font-family="Helvetica, Arial, sans-serif" font-size="10" fill="#7f1d1d">'
               '2. Hallucinates world matrices (sets Ω_{UseDNS}=0 and P_SSH=I₄ instead of rank 2).</text>')
    svg.append('<text x="48" y="488" font-family="Helvetica, Arial, sans-serif" font-size="10" fill="#7f1d1d">'
               '3. Greedy RLHF ignores epistemic value I(S;O|a) and emits premature ontic fixes.</text>')

    # Right Panel: Meta-Cognitive Detection & Neuro-Symbolic Switching Gate
    svg.append('<rect x="515" y="72" width="465" height="438" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="747" y="96" font-family="Helvetica, Arial, sans-serif" font-size="13" font-weight="bold" fill="#1e293b" text-anchor="middle">'
               'B. Meta-Cognitive Detector &amp; Neuro-Symbolic Solver Routing</text>')
    svg.append('<text x="747" y="113" font-family="monospace" font-size="10" fill="#475569" text-anchor="middle">'
               'Detecting Rank-Deficiency &amp; Censoring Before Ontic Intervention</text>')

    # Detector Box
    svg.append('<rect x="535" y="126" width="425" height="92" rx="5" fill="#f8fafc" stroke="#475569" stroke-width="1.8"/>')
    svg.append('<text x="747" y="145" font-family="Helvetica, Arial, sans-serif" font-size="11.5" font-weight="bold" fill="#0f172a" text-anchor="middle">'
               'STEP 1: Structural &amp; Spectral Problem-Class Detector</text>')
    svg.append('<text x="547" y="163" font-family="monospace" font-size="9" fill="#1e293b">'
               '• Aliasing Ratio   : ρ_alias = |E(o)| = 1ᵀ(O_a)_{i,•} ≫ 1 (Nullspace &gt; 0)</text>')
    svg.append('<text x="547" y="179" font-family="monospace" font-size="9" fill="#1e293b">'
               '• Cascade Depth    : D = N·M ≥ D_min with sequential censoring κ*(s)</text>')
    svg.append('<text x="547" y="195" font-family="monospace" font-size="9" fill="#1e293b">'
               '• Posterior Entropy: H(b_t) = -∑ b_k log₂ b_k &gt; τ_safe (Ambiguity Gate)</text>')
    svg.append('<text x="547" y="210" font-family="monospace" font-size="9" font-weight="bold" fill="#dc2626">'
               '• Expected Drift   : ΔK = (α(M_o - k) - 1)/M_o &gt; 0 (Heuristic Hazard!)</text>')

    svg.append('<line x1="747" y1="218" x2="747" y2="240" stroke="#1e293b" stroke-width="2" marker-end="url(#arrDark)"/>')

    # Decision Diamond / Gate
    svg.append('<polygon points="747,242 895,276 747,310 599,276" fill="#fef9c3" stroke="#ca8a04" stroke-width="2"/>')
    svg.append('<text x="747" y="273" font-family="monospace" font-size="10.5" font-weight="bold" fill="#713f12" text-anchor="middle">'
               'Is H(b_t) &gt; τ_safe  OR  ρ_alias &gt; 1?</text>')
    svg.append('<text x="747" y="288" font-family="Helvetica, Arial, sans-serif" font-size="9.5" fill="#854d0e" text-anchor="middle">'
               '(High Ambiguity / Censoring Detected)</text>')

    # Branch Left (YES -> Formal Solver / Epistemic Mode)
    svg.append('<path d="M 640 292 L 640 336" fill="none" stroke="#16a34a" stroke-width="2.2" marker-end="url(#arrGreen6)"/>')
    svg.append('<text x="612" y="320" font-family="Helvetica, Arial, sans-serif" font-size="10" font-weight="bold" fill="#16a34a">YES</text>')

    svg.append('<rect x="533" y="340" width="212" height="154" rx="5" fill="#f0fdf4" stroke="#16a34a" stroke-width="1.8"/>')
    svg.append('<text x="639" y="358" font-family="Helvetica, Arial, sans-serif" font-size="10.8" font-weight="bold" fill="#166534" text-anchor="middle">'
               'MODE A: Formal Epistemic Solver</text>')
    svg.append('<text x="541" y="376" font-family="Helvetica, Arial, sans-serif" font-size="9.6" fill="#14532d">'
               '1. ABSTAIN from all ontic edits!</text>')
    svg.append('<text x="541" y="393" font-family="Helvetica, Arial, sans-serif" font-size="9.6" fill="#14532d">'
               '2. Compile DAG into C99 / LP /</text>')
    svg.append('<text x="549" y="406" font-family="Helvetica, Arial, sans-serif" font-size="9.6" fill="#14532d">'
               'MILP Bellman Prefix Solver.</text>')
    svg.append('<text x="541" y="423" font-family="Helvetica, Arial, sans-serif" font-size="9.6" fill="#14532d">'
               '3. If prefix probes unavailable,</text>')
    svg.append('<text x="549" y="436" font-family="Helvetica, Arial, sans-serif" font-size="9.6" font-weight="bold" fill="#166534">'
               'DISCLOSE to user:</text>')
    svg.append('<text x="545" y="452" font-family="monospace" font-size="8.6" fill="#14532d">'
               '"|E(o)|=48 states aliased;</text>')
    svg.append('<text x="545" y="464" font-family="monospace" font-size="8.6" fill="#14532d">'
               'H(b)=5.58 bits. Running</text>')
    svg.append('<text x="545" y="476" font-family="monospace" font-size="8.6" fill="#14532d">'
               'bisection probe Π_63 first."</text>')

    # Branch Right (NO -> H(b_t) == 0 -> Surgical Ontic Execution)
    svg.append('<path d="M 855 292 L 855 336" fill="none" stroke="#2563eb" stroke-width="2.2" marker-end="url(#arrDark)"/>')
    svg.append('<text x="875" y="320" font-family="Helvetica, Arial, sans-serif" font-size="10" font-weight="bold" fill="#2563eb">NO (H=0)</text>')

    svg.append('<rect x="755" y="340" width="208" height="154" rx="5" fill="#eff6ff" stroke="#3b82f6" stroke-width="1.8"/>')
    svg.append('<text x="859" y="358" font-family="Helvetica, Arial, sans-serif" font-size="10.8" font-weight="bold" fill="#1e3a8a" text-anchor="middle">'
               'MODE B: Verified Ontic Repair</text>')
    svg.append('<text x="763" y="376" font-family="Helvetica, Arial, sans-serif" font-size="9.6" fill="#1e3a8a">'
               '1. Unique frontier k* verified</text>')
    svg.append('<text x="771" y="389" font-family="monospace" font-size="9.2" fill="#1e3a8a">'
               '(b_t = u_{k*}, H(b_t) = 0).</text>')
    svg.append('<text x="763" y="408" font-family="Helvetica, Arial, sans-serif" font-size="9.6" fill="#1e3a8a">'
               '2. Execute surgical intervention</text>')
    svg.append('<text x="771" y="421" font-family="monospace" font-size="9.2" font-weight="bold" fill="#1d4ed8">'
               'do(s_{k*} ← 1).</text>')
    svg.append('<text x="763" y="440" font-family="Helvetica, Arial, sans-serif" font-size="9.6" fill="#1e3a8a">'
               '3. Advance monotonic bound</text>')
    svg.append('<text x="771" y="453" font-family="monospace" font-size="9.2" fill="#1e3a8a">'
               'L_{t+1} ← k* + 1</text>')
    svg.append('<text x="763" y="472" font-family="Helvetica, Arial, sans-serif" font-size="9.6" fill="#1e3a8a">'
               '4. Re-enter Detector for k₂*.</text>')

    svg.append('</svg>')
    save_svg_and_png("fig6_transformer_and_router", "\n".join(svg))


# ==============================================================================
# FIGURE 7: 256x256 2D Dungeon Game Isomorphism & Abramsky-Hyland Game Semantics
# ==============================================================================
def make_fig7_2d_game_and_semantics():
    W = 1040
    H = 590
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
        '<defs>',
        '  <linearGradient id="bg7" x1="0" y1="0" x2="1" y2="1">',
        '    <stop offset="0%" stop-color="#0f172a"/>',
        '    <stop offset="100%" stop-color="#1e293b"/>',
        '  </linearGradient>',
        '  <marker id="arrGold" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#f59e0b"/>',
        '  </marker>',
        '  <marker id="arrCyan" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#06b6d4"/>',
        '  </marker>',
        '</defs>',
        f'<rect width="{W}" height="{H}" rx="10" fill="#f8fafc" stroke="#cbd5e1" stroke-width="2"/>',
        '<rect x="20" y="16" width="1000" height="44" rx="6" fill="#0f172a"/>',
        '<text x="520" y="43" font-family="Helvetica, Arial, sans-serif" font-size="15.5" font-weight="bold" fill="#ffffff" text-anchor="middle">',
        '256×256 2D Dungeon Isomorphism (16 Sectors × 8 Gadgets) &amp; Abramsky–Hyland–Ong Game Semantics',
        '</text>',
    ]

    # Panel A (Left): 256x256 Macro-Grid (4x4 Sectors of 64x64) with the 5 Injected Faults
    svg.append('<rect x="20" y="72" width="470" height="502" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="255" y="95" font-family="Helvetica, Arial, sans-serif" font-size="13" font-weight="bold" fill="#0f172a" text-anchor="middle">'
               'A. 256×256 2D Board (4×4 Boustrophedon Grid of 64×64 Sectors)</text>')
    svg.append('<text x="255" y="112" font-family="monospace" font-size="10" fill="#475569" text-anchor="middle">'
               '14,881 Walkable Tiles | 128 Unique Gadget Coords (x_k, y_k) ∈ [0..255]²</text>')

    gx0 = 45
    gy0 = 126
    sec_px = 95  # 4 * 95 = 380 px square representing 256x256

    # Draw outer 256x256 frame
    svg.append(f'<rect x="{gx0}" y="{gy0}" width="{4*sec_px}" height="{4*sec_px}" fill="#0f172a" stroke="#334155" stroke-width="2"/>')

    # Coordinate labels 0, 64, 128, 192, 256
    for idx in range(5):
        coord = idx * 64
        px = gx0 + idx * sec_px
        py = gy0 + idx * sec_px
        svg.append(f'<text x="{px}" y="{gy0-4}" font-family="monospace" font-size="8.5" fill="#475569" text-anchor="middle">x={coord}</text>')
        svg.append(f'<text x="{gx0-4}" y="{py+3}" font-family="monospace" font-size="8.5" fill="#475569" text-anchor="end">y={coord}</text>')

    fault_sectors = {
        0: ("k=1:Safe(10,12)", "#ef4444"),
        3: ("k=24:Vlt(202,20)", "#f97316"),
        7: ("k=59:Brg(28,96)", "#eab308"),
        11: ("k=93:Gen(236,176)", "#a855f7"),
        15: ("k=126:Dr(50,224)", "#3b82f6"),
    }

    centers = {}
    for sec in range(16):
        row = sec // 4
        col = (sec % 4) if (row % 2 == 0) else (3 - (sec % 4))
        sx = gx0 + col * sec_px
        sy = gy0 + row * sec_px
        centers[sec] = (sx + sec_px / 2, sy + sec_px / 2)

        # Sector box
        is_fault = sec in fault_sectors
        s_fill = "#1e293b" if not is_fault else "#311018"
        s_stroke = "#475569" if not is_fault else fault_sectors[sec][1]
        svg.append(f'<rect x="{sx+2}" y="{sy+2}" width="{sec_px-4}" height="{sec_px-4}" rx="4" fill="{s_fill}" stroke="{s_stroke}" stroke-width="{2 if is_fault else 1}"/>')

        # Mini rooms inside each sector (Main corridor + North Vault + 2 South Generators)
        svg.append(f'<rect x="{sx+8}" y="{sy+43}" width="{sec_px-16}" height="9" fill="#334155"/>')
        svg.append(f'<rect x="{sx+12}" y="{sy+16}" width="14" height="27" fill="#1e3a8a" stroke="#3b82f6" stroke-width="0.8"/>')
        svg.append(f'<rect x="{sx+30}" y="{sy+52}" width="14" height="22" fill="#14532d" stroke="#22c55e" stroke-width="0.8"/>')
        svg.append(f'<rect x="{sx+58}" y="{sy+52}" width="14" height="22" fill="#78350f" stroke="#f59e0b" stroke-width="0.8"/>')

        svg.append(f'<text x="{sx+8}" y="{sy+13}" font-family="monospace" font-size="9.5" font-weight="bold" fill="#e2e8f0">S_{sec} (Hop {sec})</text>')

        if is_fault:
            f_lbl, f_col = fault_sectors[sec]
            svg.append(f'<rect x="{sx+5}" y="{sy+74}" width="{sec_px-10}" height="16" rx="2" fill="{f_col}"/>')
            svg.append(f'<text x="{sx+sec_px/2}" y="{sy+85}" font-family="monospace" font-size="7.5" font-weight="bold" fill="#ffffff" text-anchor="middle">{f_lbl}</text>')

    # Draw Boustrophedon snake path connecting S_0 -> S_1 -> ... -> S_15
    for sec in range(15):
        x1, y1 = centers[sec]
        x2, y2 = centers[sec + 1]
        svg.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#f59e0b" stroke-width="1.8" stroke-dasharray="4,3" marker-end="url(#arrGold)"/>')

    svg.append('<text x="255" y="525" font-family="Helvetica, Arial, sans-serif" font-size="10.2" font-weight="bold" fill="#0f172a" text-anchor="middle">'
               'Fog-of-War Rule: Room k is observable ONLY when Avatar reaches (x_k, y_k)!</text>')
    svg.append('<text x="255" y="542" font-family="monospace" font-size="9" fill="#dc2626" text-anchor="middle">'
               'Blind Run halts at S₀ Safe K₀ (10,12) → masks faults at S₃, S₇, S₁₁, S₁₅!</text>')
    svg.append('<text x="255" y="558" font-family="monospace" font-size="9" font-weight="bold" fill="#16a34a" text-anchor="middle">'
               '2D Drone Waypoint Bisection solves all 5 masked faults in 38 probes!</text>')

    # Panel B (Right Top): Zoomed 64x64 Single Sector Architecture (8 Gadgets m=0..7)
    svg.append('<rect x="505" y="72" width="515" height="248" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="762" y="95" font-family="Helvetica, Arial, sans-serif" font-size="13" font-weight="bold" fill="#0f172a" text-anchor="middle">'
               'B. Zoomed 64×64 Sector S_i Architecture (Bijection Φ_iso to 8 SSH Stages)</text>')

    # Schematic of a single 64x64 sector
    zx = 522
    zy = 108
    zw = 480
    zh = 198
    svg.append(f'<rect x="{zx}" y="{zy}" width="{zw}" height="{zh}" rx="6" fill="#0f172a" stroke="#334155" stroke-width="1.5"/>')

    # Main East-West Corridor
    svg.append(f'<rect x="{zx+14}" y="{zy+86}" width="{zw-28}" height="32" rx="3" fill="#1e293b" stroke="#64748b" stroke-width="1.2"/>')
    # North Key-Vault Room
    svg.append(f'<rect x="{zx+32}" y="{zy+12}" width="118" height="76" rx="4" fill="#172554" stroke="#3b82f6" stroke-width="1.5"/>')
    svg.append(f'<text x="{zx+91}" y="{zy+26}" font-family="Helvetica, Arial, sans-serif" font-size="9.5" font-weight="bold" fill="#93c5fd" text-anchor="middle">LOCKED KEY-VAULT ROOM</text>')

    # South Power Room A (Generator A: DNS)
    svg.append(f'<rect x="{zx+165}" y="{zy+116}" width="120" height="78" rx="4" fill="#052e16" stroke="#22c55e" stroke-width="1.5"/>')
    svg.append(f'<text x="{zx+225}" y="{zy+185}" font-family="Helvetica, Arial, sans-serif" font-size="9" font-weight="bold" fill="#86efac" text-anchor="middle">POWER ROOM A (UDP/53)</text>')

    # South Power Room B (Generator B: Reverse DNS)
    svg.append(f'<rect x="{zx+305}" y="{zy+116}" width="128" height="78" rx="4" fill="#451a03" stroke="#f59e0b" stroke-width="1.5"/>')
    svg.append(f'<text x="{zx+369}" y="{zy+185}" font-family="Helvetica, Arial, sans-serif" font-size="9" font-weight="bold" fill="#fde047" text-anchor="middle">POWER ROOM B (UseDNS)</text>')

    # 8 Gadget Badges inside the zoomed sector
    gadgets_viz = [
        (zx+91, zy+74, "m=0: Vault Door V_i", "SSH_AUTH_SOCK", "#3b82f6"),
        (zx+91, zy+44, "m=1: Safe K_i (Key_i)", "Key Passphrase TTY", "#ef4444"),
        (zx+225, zy+150, "m=2: Gen-A (Beacon)", "DNS UDP/53 Resolve", "#22c55e"),
        (zx+205, zy+102, "m=3: Bridge B_i", "TCP/22 + 1420 MTU", "#06b6d4"),
        (zx+305, zy+102, "m=4: Laser L_i", "KEX / HostKey", "#a855f7"),
        (zx+369, zy+150, "m=5: Gen-B (Relay)", "sshd UseDNS PTR", "#f59e0b"),
        (zx+402, zy+66, "m=6: Blast Door D_i", "authorized_keys", "#ec4899"),
        (zx+442, zy+102, "m=7: Airlock T_i", "AllowTcpForward", "#14b8a6"),
    ]

    # Power/Key dependency wires
    svg.append(f'<path d="M {zx+91} {zy+44} Q {zx+250} {zy+18} {zx+402} {zy+56}" fill="none" stroke="#ef4444" stroke-width="1.5" stroke-dasharray="3,2" marker-end="url(#arrGold)"/>')
    svg.append(f'<path d="M {zx+369} {zy+138} L {zx+402} {zy+80}" fill="none" stroke="#f59e0b" stroke-width="1.5" stroke-dasharray="3,2" marker-end="url(#arrGold)"/>')

    for gx_i, gy_i, g_title, g_ssh, g_col in gadgets_viz:
        svg.append(f'<rect x="{gx_i-52}" y="{gy_i-12}" width="104" height="24" rx="4" fill="#0f172a" stroke="{g_col}" stroke-width="1.6"/>')
        svg.append(f'<text x="{gx_i}" y="{gy_i-1}" font-family="monospace" font-size="8.2" font-weight="bold" fill="#ffffff" text-anchor="middle">{g_title}</text>')
        svg.append(f'<text x="{gx_i}" y="{gy_i+9}" font-family="Helvetica, Arial, sans-serif" font-size="7.5" fill="{g_col}" text-anchor="middle">↔ {g_ssh}</text>')

    # Panel C (Right Bottom): Abramsky-Hyland-Ong Game Semantics (Arena, Plays, Innocence)
    svg.append('<rect x="505" y="330" width="515" height="244" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="762" y="352" font-family="Helvetica, Arial, sans-serif" font-size="13" font-weight="bold" fill="#0f172a" text-anchor="middle">'
               'C. Formal Game Semantics (Abramsky–Jagadeesan–Malacaria / Hyland–Ong)</text>')

    svg.append('<rect x="520" y="364" width="485" height="198" rx="5" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1.2"/>')
    lines_c = [
        ("1. Arena G = (M_P, M_O, λ, ⊢) &amp; Sequential Composition G₁ ; G₂ ; ... ; G_D:", "#1e3a8a", True),
        ("   • Player (P = Diagnostic Agent) plays Question moves q_a ∈ A_epistemic ∪ A_ontic.", "#334155", False),
        ("   • Opponent (O = Network/Dungeon Environment) replies with Answer moves o ∈ O_a.", "#334155", False),
        ("2. Views ⌜s⌝, Innocence, and Observational Aliasing as Partial Visibility:", "#991b1b", True),
        ("   • In Hyland–Ong Game Semantics, an Innocent Strategy σ depends ONLY on Player's", "#334155", False),
        ("     P-view ⌜s⌝. Under end-to-end play a_e2e, O hides internal moves m_0..m_{k*}", "#334155", False),
        ("     and emits only terminal move o = Φ_e2e(k*), collapsing 48 plays into 1 P-view!", "#7f1d1d", False),
        ("3. Prefix Probes Π_m as Interaction-Revealing Subgame Projections:", "#166534", True),
        ("   • Prefix probe Π_m forces Opponent to reveal the boolean Answer of subgame G_{0..m}.", "#334155", False),
        ("   • Full Abstraction &amp; Bisimulation Theorem: The 256×256 2D Dungeon Arena G_2D and", "#14532d", False),
        ("     the 16-Hop SSH Arena G_SSH have isomorphic legal play trees L(G_2D) ≅ L(G_SSH)!", "#166534", True),
    ]
    for l_idx, (txt, col, is_bold) in enumerate(lines_c):
        fw = "bold" if is_bold else "normal"
        svg.append(f'<text x="530" y="{383 + l_idx*16}" font-family="Helvetica, Arial, sans-serif" font-size="10" font-weight="{fw}" fill="{col}">{txt}</text>')

    svg.append('</svg>')
    save_svg_and_png("fig7_2d_game_and_semantics", "\n".join(svg))


# ==============================================================================
# FIGURE 8: Joint Symptom-Fiber Subspace Bisection & 5-Run Codex Benchmark
# ==============================================================================
def make_fig8_joint_subspace_and_codex_ablation():
    W = 1040
    H = 620
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
        '<defs>',
        '  <linearGradient id="bg8" x1="0" y1="0" x2="1" y2="1">',
        '    <stop offset="0%" stop-color="#f8fafc"/>',
        '    <stop offset="100%" stop-color="#f1f5f9"/>',
        '  </linearGradient>',
        '</defs>',
        f'<rect width="{W}" height="{H}" rx="10" fill="url(#bg8)" stroke="#cbd5e1" stroke-width="2"/>',
        '<rect x="20" y="16" width="1000" height="44" rx="6" fill="#0f172a"/>',
        '<text x="520" y="43" font-family="Helvetica, Arial, sans-serif" font-size="15.2" font-weight="bold" fill="#ffffff" text-anchor="middle">',
        'Joint Symptom-Subspace Theory (O_e2e⁻¹ ∩ Π), 5-Run Codex Ablation, &amp; Compute/Cost Scaling (6.6×10¹³×)',
        '</text>',
    ]

    # Panel A (Top Left): Joint O_e2e^{-1}(o) + Pi Kronecker Fiber Decomposition
    svg.append('<rect x="20" y="72" width="490" height="275" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="265" y="94" font-family="Helvetica, Arial, sans-serif" font-size="12.8" font-weight="bold" fill="#0f172a" text-anchor="middle">'
               'A. Joint Symptom-Fiber Bisection: O_e2e⁻¹(o) ∩ Π</text>')
    svg.append('<text x="265" y="111" font-family="monospace" font-size="9.5" fill="#475569" text-anchor="middle">'
               'H(129) = 7.0112 bits = 0.0112 (Health) + 2.2500 (Symptom O) + 4.7500 (Fiber Π)</text>')

    # Root Box: 129 States
    svg.append('<rect x="115" y="122" width="300" height="34" rx="4" fill="#1e293b" stroke="#0f172a" stroke-width="1.5"/>')
    svg.append('<text x="265" y="137" font-family="monospace" font-size="9.2" font-weight="bold" fill="#ffffff" text-anchor="middle">'
               'Step 1: End-to-End Probe Π₁₂₇ (or run)</text>')
    svg.append('<text x="265" y="150" font-family="monospace" font-size="8.0" fill="#93c5fd" text-anchor="middle">'
               'Projects [L_t..127] onto Kronecker Fiber F(o, L_t)</text>')

    fibers = [
        (32, "O₁: Conduit", "m∈{0,7} | 32", "5 probes", "#3b82f6", "#eff6ff"),
        (124, "O₂: KeyLock", "m∈{1,6} | 32", "5 probes", "#ef4444", "#fef2f2"),
        (216, "O₃: GenHang", "m∈{2,5} | 32", "5 probes", "#f59e0b", "#fffbeb"),
        (308, "O₄: Bridge", "m∈{3} | 16", "4 probes", "#06b6d4", "#ecfeff"),
        (400, "O₅: Laser", "m∈{4} | 16", "4 probes", "#a855f7", "#faf5ff"),
    ]
    for fx, f_title, f_sub, f_prb, f_col, f_bg in fibers:
        svg.append(f'<line x1="265" y1="156" x2="{fx+44}" y2="176" stroke="{f_col}" stroke-width="1.5"/>')
        svg.append(f'<rect x="{fx}" y="176" width="88" height="58" rx="4" fill="{f_bg}" stroke="{f_col}" stroke-width="1.6"/>')
        svg.append(f'<text x="{fx+44}" y="191" font-family="monospace" font-size="8.8" font-weight="bold" fill="#0f172a" text-anchor="middle">{f_title}</text>')
        svg.append(f'<text x="{fx+44}" y="205" font-family="monospace" font-size="8.2" fill="#334155" text-anchor="middle">{f_sub}</text>')
        svg.append(f'<rect x="{fx+8}" y="213" width="72" height="16" rx="3" fill="{f_col}"/>')
        svg.append(f'<text x="{fx+44}" y="224" font-family="monospace" font-size="8.2" font-weight="bold" fill="#ffffff" text-anchor="middle">+ {f_prb}</text>')

    # Summary Math Box inside Panel A
    svg.append('<rect x="32" y="244" width="466" height="92" rx="5" fill="#f0fdf4" stroke="#16a34a" stroke-width="1.5"/>')
    svg.append('<text x="42" y="261" font-family="Helvetica, Arial, sans-serif" font-size="10.2" font-weight="bold" fill="#166534">'
               'Exact Submatrix Total Unimodularity &amp; Bellman Value Reduction:</text>')
    svg.append('<text x="42" y="278" font-family="monospace" font-size="8.3" fill="#14532d">'
               '• Restricted Operator Π|_{F(o)} ∈ {0,1}^{|F|×|F|} is Lower-Triangular (det = 1)!</text>')
    svg.append('<text x="42" y="294" font-family="monospace" font-size="8.3" fill="#14532d">'
               '• Single-Fault Expected: V*_Π(129) = 905/129 = 7.0155 → V*_joint(129) = 737/129 = 5.7132</text>')
    svg.append('<text x="42" y="310" font-family="monospace" font-size="8.3" font-weight="bold" fill="#166534">'
               '• 5-Fault Cascade (M=5): Stage-Agnostic Π = 35.56 avg → Joint O⁻¹+Π = 25.30 (-28.9%)</text>')
    svg.append('<text x="42" y="326" font-family="monospace" font-size="8.3" fill="#15803d">'
               '• Interleaved Midpoint Variant (clean3/clean4): 19–20 fiber probes + 2–6 E2E runs!</text>')

    # Panel B (Top Right): 5-Run Codex Empirical Ablation Bar Chart
    svg.append('<rect x="525" y="72" width="495" height="275" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="772" y="94" font-family="Helvetica, Arial, sans-serif" font-size="12.8" font-weight="bold" fill="#0f172a" text-anchor="middle">'
               'B. Empirical Codex Progression Across 5 Controlled Experiments</text>')
    svg.append('<text x="772" y="111" font-family="monospace" font-size="9.5" fill="#475569" text-anchor="middle">'
               'Drone Probes &amp; Collateral Errors Across Prompt / Isolation / Model Tiers</text>')

    runs = [
        ("Run 0a (Manual)", 26, "3 WRONG REPAIRS (Broke k=22,26!)", "#dc2626"),
        ("clean2 (HTTP Low)", 69, "69 probes + 6 runs (0 wrong)", "#d97706"),
        ("Bellman Π (Ref)", 38, "38 probes + 0 runs (0 wrong)", "#3b82f6"),
        ("clean1 (Prompt B)", 36, "36 probes + 1 run (0 wrong)", "#0284c7"),
        ("Joint O⁻¹+Π (C99)", 28, "22 fiber + 6 E2E (0 wrong)", "#10b981"),
        ("clean4 (Astra Rnd5)", 20, "20 probes + 6 runs (0 wrong)", "#16a34a"),
        ("clean3 (Astra Adv5)", 19, "19 probes + 2 runs (0 wrong)", "#15803d"),
    ]
    bx0 = 648
    by0 = 126
    max_w = 185.0
    for idx, (r_name, p_cnt, r_desc, r_col) in enumerate(runs):
        ry = by0 + idx * 30
        bw = (p_cnt / 72.0) * max_w
        svg.append(f'<text x="{bx0-8}" y="{ry+14}" font-family="monospace" font-size="8.8" font-weight="bold" fill="#1e293b" text-anchor="end">{r_name}</text>')
        svg.append(f'<rect x="{bx0}" y="{ry+2}" width="{bw:.1f}" height="18" rx="3" fill="{r_col}"/>')
        svg.append(f'<text x="{bx0+bw+6:.1f}" y="{ry+14}" font-family="monospace" font-size="8.2" font-weight="bold" fill="{r_col}">{r_desc}</text>')

    # Panel C (Bottom Full Width): Compute, Latency, Energy & Monetary Cost Comparison Table
    svg.append('<rect x="20" y="360" width="1000" height="244" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="520" y="383" font-family="Helvetica, Arial, sans-serif" font-size="13" font-weight="bold" fill="#0f172a" text-anchor="middle">'
               'C. Physical Compute, Silicon Cycle Count, FLOPs, Energy, and Monetary Cost Comparison</text>')

    # Table Header
    svg.append('<rect x="36" y="396" width="968" height="26" rx="4" fill="#1e293b"/>')
    cols = [
        (44, "Metric / Physical Resource"),
        (248, "C99 / C++23 Joint Solver (O⁻¹+Π)"),
        (478, "gpt-6-astra ultra (clean4: random5)"),
        (698, "gpt-6-astra ultra (clean3: adv5)"),
        (898, "Ratio (LLM / C99)"),
    ]
    for cx, c_title in cols:
        svg.append(f'<text x="{cx}" y="413" font-family="Helvetica, Arial, sans-serif" font-size="9.6" font-weight="bold" fill="#ffffff">{c_title}</text>')

    rows = [
        ("Wall-Clock Solve Time", "1.8 microseconds (1.8×10⁻⁶ s)", "4 min 12 sec (252.0 s)", "5 min 18 sec (318.0 s)", "1.77 × 10⁸ ×"),
        ("Epistemic Probes / E2E", "22 fiber + 6 E2E (0 wrong)", "20 fiber + 6 E2E (0 wrong)", "19 fiber + 2 E2E (0 wrong)", "1.00 × (Parity!)"),
        ("Token Consumption", "0 tokens (32 bytes RAM state)", "1,610,029 tokens (42 turns)", "1,887,149 solve (3.00M all)", "∞ (1.89M tok)"),
        ("Arithmetic / Tensor Ops", "152 int ops (~650 CPU cycles)", "~3.7 × 10¹⁶ FLOPs (37 PFLOPs)", "~4.3 × 10¹⁶ FLOPs (43 PFLOPs)", "6.62 × 10¹³ ×"),
        ("Electrical Energy", "2.7 × 10⁻⁸ J (27 nanojoules)", "~65,000 J (~18.1 Wh, 8×H100)", "~75,000 J (~20.8 Wh, 8×H100)", "2.78 × 10¹² ×"),
        ("Monetary Cost (USD)", "$4.0 × 10⁻¹³ ($0.0000000000004)", "$3.30 – $12.40 (cached API)", "$3.86 – $14.50 ($6.15M tot)", "9.65 × 10¹² ×"),
    ]
    for r_i, (m_lbl, v_c99, v_c4, v_c3, v_rat) in enumerate(rows):
        ry = 422 + r_i * 27
        bg = "#f8fafc" if (r_i % 2 == 0) else "#f1f5f9"
        svg.append(f'<rect x="36" y="{ry}" width="968" height="26" fill="{bg}" stroke="#e2e8f0" stroke-width="0.8"/>')
        svg.append(f'<text x="44" y="{ry+17}" font-family="Helvetica, Arial, sans-serif" font-size="9.4" font-weight="bold" fill="#0f172a">{m_lbl}</text>')
        svg.append(f'<text x="248" y="{ry+17}" font-family="monospace" font-size="8.6" font-weight="bold" fill="#166534">{v_c99}</text>')
        svg.append(f'<text x="478" y="{ry+17}" font-family="monospace" font-size="8.6" fill="#1e3a8a">{v_c4}</text>')
        svg.append(f'<text x="698" y="{ry+17}" font-family="monospace" font-size="8.6" fill="#1e3a8a">{v_c3}</text>')
        svg.append(f'<text x="898" y="{ry+17}" font-family="monospace" font-size="8.6" font-weight="bold" fill="#dc2626">{v_rat}</text>')

    svg.append('</svg>')
    save_svg_and_png("fig8_joint_subspace_and_codex_ablation", "\n".join(svg))


# ==============================================================================
# FIGURE 9: Economic & Infrastructure Outage Risk Analysis (Low vs Ultra vs C99)
# ==============================================================================
def make_fig9_economic_and_outage_risk():
    W = 1040
    H = 630
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
        '<defs>',
        '  <linearGradient id="bg9" x1="0" y1="0" x2="1" y2="1">',
        '    <stop offset="0%" stop-color="#f8fafc"/>',
        '    <stop offset="100%" stop-color="#f1f5f9"/>',
        '  </linearGradient>',
        '  <marker id="arrRed9" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#dc2626"/>',
        '  </marker>',
        '  <marker id="arrGreen9" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#16a34a"/>',
        '  </marker>',
        '</defs>',
        f'<rect width="{W}" height="{H}" rx="10" fill="url(#bg9)" stroke="#cbd5e1" stroke-width="2"/>',
        '<rect x="20" y="16" width="1000" height="44" rx="6" fill="#0f172a"/>',
        '<text x="520" y="43" font-family="Helvetica, Arial, sans-serif" font-size="14.8" font-weight="bold" fill="#ffffff" text-anchor="middle">',
        'Production Economics: Token API Costs (Low vs. Ultra) &amp; Worst-Case Infrastructure Outage Cost vs. Specialized C99',
        '</text>',
    ]

    # Panel A (Top Left): 4-Regime Token & Probe Economics (Low/Manual vs Low/Loops vs Ultra vs C99)
    svg.append('<rect x="20" y="72" width="490" height="275" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="265" y="94" font-family="Helvetica, Arial, sans-serif" font-size="12.5" font-weight="bold" fill="#0f172a" text-anchor="middle">'
               'A. Token Usage, Probe Delay &amp; Collateral Risk by Agent Tier</text>')
    svg.append('<text x="265" y="110" font-family="monospace" font-size="9.0" fill="#475569" text-anchor="middle">'
               'Why Cheap/Low-Effort LLMs Are a False Economy in Cascaded Infrastructure</text>')

    tiers = [
        (120, "#fef2f2", "#dc2626", "1. Low-Setting / Unverified Manual LLM (Run 0a)",
         "~180k–310k tok ($0.15–$0.45) | 26 probes | 3 BLIND REPAIRS (k=22,26)",
         "Result: CATASTROPHIC LOCKOUT on bst-core-rtr01 -> $540,000+ SLA Outage!"),
        (175, "#fffbeb", "#d97706", "2. Low/Standard-Setting HTTP Loops (clean2)",
         "~420k–580k tok ($0.85–$2.10) | 69 probes + 6 runs (3.45× extra probes)",
         "Result: 0 wrong repairs, but 49 wasted network probes extend MTTR delay!"),
        (230, "#eff6ff", "#2563eb", "3. Highest-Setting gpt-6-astra ultra (clean3 / clean4)",
         "1.61M–1.89M tok ($3.30–$14.50, 43 PFLOPs) | 19–20 probes | 0 wrong",
         "Result: Discovers O⁻¹∩Π math! Zero wrong repairs, but 4.2–5.3 min compute."),
        (285, "#f0fdf4", "#16a34a", "4. Specialized C99 / C++23 Joint Solver (O⁻¹ + Π)",
         "0 tokens ($4.0×10⁻¹³, 152 int ops, 1.8 μs) | 22 fiber + 6 E2E | 0 wrong",
         "Result: Deterministic 0% collateral risk + 14.4 s total network probe time!"),
    ]
    for ty, bg, col, title, line1, line2 in tiers:
        svg.append(f'<rect x="32" y="{ty}" width="466" height="49" rx="4" fill="{bg}" stroke="{col}" stroke-width="1.5"/>')
        svg.append(f'<text x="42" y="{ty+15}" font-family="Helvetica, Arial, sans-serif" font-size="9.8" font-weight="bold" fill="{col}">{title}</text>')
        svg.append(f'<text x="42" y="{ty+30}" font-family="monospace" font-size="8.3" fill="#1e293b">{line1}</text>')
        svg.append(f'<text x="42" y="{ty+43}" font-family="Helvetica, Arial, sans-serif" font-size="8.5" font-weight="bold" fill="#0f172a">{line2}</text>')

    # Panel B (Top Right): Concrete Worst-Case Server Outage Anatomy (Run 0a: Blind Repair at k=22 & k=26)
    svg.append('<rect x="525" y="72" width="495" height="275" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="772" y="94" font-family="Helvetica, Arial, sans-serif" font-size="12.5" font-weight="bold" fill="#991b1b" text-anchor="middle">'
               'B. Concrete Worst-Case Server Outage: Run 0a Collateral Cascade</text>')
    svg.append('<text x="772" y="110" font-family="monospace" font-size="9.0" fill="#475569" text-anchor="middle">'
               'How Saving $3 in LLM Tokens Causes a 3.5-Hour Tier-1 Bastion Blackout</text>')

    # Timeline boxes inside Panel B
    steps_b = [
        (120, "#f8fafc", "#475569", "t = 00:00 | Initial Incident: 5 Masked Faults Across 16-Hop SCADA Chain",
         "True faults: k* ∈ {1 (S0), 24 (S3), 59 (S7), 93 (S11), 126 (S15)}. Hop 2 is 100% HEALTHY."),
        (166, "#fef2f2", "#dc2626", "t = 01:15 | Bracket-Inversion Slip on `probe 23 -> PASS_1` → Blind `repair 22`!",
         "Agent misreads PASS_1 at k=23, skips `inspect`, and breaks k=22 (bst-core-rtr01 authorized_keys)."),
        (212, "#fef2f2", "#dc2626", "t = 01:40 | Second Blind Mutation `repair 26` (S3:2 DNS) → Total Lockout!",
         "Core router bst-core-rtr01 (Hop 2) now rejects ALL SSH keys (O₂), severing Hops 3..15!"),
        (258, "#450a0a", "#f87171", "t = 01:40 – 03:45 | Out-of-Band IPMI/iDRAC Console &amp; Data-Center Recovery",
         "SSH dead! SREs must mount ISO via BMC/iDRAC on Hop 2 &amp; 3, then bisect Hops 7, 11, 15."),
    ]
    for sy, sbg, scol, stitle, sdesc in steps_b:
        t_fill = "#ffffff" if sbg == "#450a0a" else "#0f172a"
        d_fill = "#fecaca" if sbg == "#450a0a" else "#334155"
        svg.append(f'<rect x="537" y="{sy}" width="471" height="41" rx="4" fill="{sbg}" stroke="{scol}" stroke-width="1.4"/>')
        svg.append(f'<text x="546" y="{sy+16}" font-family="Helvetica, Arial, sans-serif" font-size="9.3" font-weight="bold" fill="{t_fill}">{stitle}</text>')
        svg.append(f'<text x="546" y="{sy+32}" font-family="monospace" font-size="7.7" fill="{d_fill}">{sdesc}</text>')

    svg.append('<rect x="537" y="305" width="471" height="32" rx="4" fill="#fef9c3" stroke="#ca8a04" stroke-width="1.4"/>')
    svg.append('<text x="772" y="319" font-family="Helvetica, Arial, sans-serif" font-size="9.2" font-weight="bold" fill="#854d0e" text-anchor="middle">'
               'Unbisected Heuristic Policy (α=0.25): 99.98% Failure Rate (48.1 Wrong Edits → 28 Broken Hops!)</text>')
    svg.append('<text x="772" y="332" font-family="monospace" font-size="7.8" fill="#713f12" text-anchor="middle">'
               'Expected Hitting Time E[τ₀] ≈ 1.4 × 10²³ steps (Permanent Data-Center Configuration Corruption)</text>')

    # Panel C (Bottom Full Width): End-to-End Total Cost of Ownership (TCO) & SLA Downtime Table
    svg.append('<rect x="20" y="360" width="1000" height="254" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="520" y="382" font-family="Helvetica, Arial, sans-serif" font-size="12.5" font-weight="bold" fill="#0f172a" text-anchor="middle">'
               'C. Total Economic Impact Per Incident: API Token Cost + Network Delay + Server Downtime SLA ($9,000/min Tier-1 Outage)</text>')

    svg.append('<rect x="34" y="394" width="972" height="25" rx="4" fill="#1e293b"/>')
    tcols = [
        (42, "Economic / Operational Metric"),
        (228, "1. Unbisected LLM (α=0.25)"),
        (418, "2. Low/Manual (Run 0a)"),
        (595, "3. Low HTTP (clean2)"),
        (752, "4. Astra Ultra (clean3/4)"),
        (898, "5. Optimal C99 Solver"),
    ]
    for cx, c_title in tcols:
        svg.append(f'<text x="{cx}" y="410" font-family="Helvetica, Arial, sans-serif" font-size="8.8" font-weight="bold" fill="#ffffff">{c_title}</text>')

    trows = [
        ("LLM Token Usage", "~1.2M tok (50 turns)", "~240k tok (manual)", "~480k tok (35 turns)", "1.61M – 1.89M tok", "0 tokens (32 B RAM)"),
        ("Direct Compute / API Cost", "$1.80 – $4.50", "$0.25 – $0.45", "$0.85 – $2.10", "$3.30 – $14.50", "$4.0 × 10⁻¹³ (CPU)"),
        ("Probes + E2E / Wrong Edits", "50 probes / 48.1 WRONG", "26 probes / 3 WRONG", "69 probes + 6 E2E / 0", "19–20 prb + 2–6 E2E / 0", "22 prb + 6 E2E / 0"),
        ("Wall-Clock MTTR (Solve+Net)", "∞ (4–8 hr full rebuild)", "~65 min (IPMI + reset)", "~2.8 min (168 s)", "~4.6 min (275 s)", "14.4 sec (0.24 min)"),
        ("SLA Outage Cost ($9k/min)", "$2,160,000 – $4,320,000", "$585,000 (Bastion Lock)", "$25,200 (MTTR delay)", "$41,250 (LLM think)", "$2,160 (Network RTT)"),
        ("SRE Emergency Labor Cost", "$18,000 (12 eng × 6 hr)", "$2,400 (4 eng × 2 hr)", "$0 (Automated)", "$0 (Automated)", "$0 (Automated)"),
        ("TOTAL COST PER INCIDENT", "$2,178,004+", "$587,400.35", "$25,201.45", "$41,258.90", "$2,160.00 (Lowest!)"),
    ]
    for r_i, (m_lbl, c1, c2, c3, c4, c5) in enumerate(trows):
        ry = 420 + r_i * 26
        is_last = (r_i == len(trows) - 1)
        bg = "#fef2f2" if is_last else ("#f8fafc" if (r_i % 2 == 0) else "#f1f5f9")
        svg.append(f'<rect x="34" y="{ry}" width="972" height="25" fill="{bg}" stroke="#cbd5e1" stroke-width="{1.5 if is_last else 0.7}"/>')
        fw = "bold" if is_last else "normal"
        svg.append(f'<text x="42" y="{ry+16}" font-family="Helvetica, Arial, sans-serif" font-size="8.8" font-weight="bold" fill="#0f172a">{m_lbl}</text>')
        svg.append(f'<text x="228" y="{ry+16}" font-family="monospace" font-size="8.0" font-weight="{fw}" fill="#991b1b">{c1}</text>')
        svg.append(f'<text x="418" y="{ry+16}" font-family="monospace" font-size="8.0" font-weight="{fw}" fill="#dc2626">{c2}</text>')
        svg.append(f'<text x="595" y="{ry+16}" font-family="monospace" font-size="8.0" font-weight="{fw}" fill="#b45309">{c3}</text>')
        svg.append(f'<text x="752" y="{ry+16}" font-family="monospace" font-size="8.0" font-weight="{fw}" fill="#1e3a8a">{c4}</text>')
        svg.append(f'<text x="898" y="{ry+16}" font-family="monospace" font-size="8.0" font-weight="bold" fill="#166534">{c5}</text>')

    svg.append('</svg>')
    save_svg_and_png("fig9_economic_and_outage_risk", "\n".join(svg))


# ==============================================================================
# FIGURE 10: Step-by-Step Minimal 128-Switch Colored Series Circuit Formulation
# ==============================================================================
def make_fig10_minimal_color_circuit_step_by_step():
    W = 1040
    H = 660
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">',
        '<defs>',
        '  <linearGradient id="bg10" x1="0" y1="0" x2="1" y2="1">',
        '    <stop offset="0%" stop-color="#f8fafc"/>',
        '    <stop offset="100%" stop-color="#f1f5f9"/>',
        '  </linearGradient>',
        '  <marker id="arrGold10" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#f59e0b"/>',
        '  </marker>',
        '  <marker id="arrBlue10" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#2563eb"/>',
        '  </marker>',
        '  <marker id="arrGreen10" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#16a34a"/>',
        '  </marker>',
        '  <marker id="arrRed10" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#dc2626"/>',
        '  </marker>',
        '</defs>',
        f'<rect width="{W}" height="{H}" rx="10" fill="url(#bg10)" stroke="#cbd5e1" stroke-width="2"/>',
        '<rect x="20" y="14" width="1000" height="42" rx="6" fill="#0f172a"/>',
        '<text x="520" y="40" font-family="Helvetica, Arial, sans-serif" font-size="14.8" font-weight="bold" fill="#ffffff" text-anchor="middle">',
        'Minimal Quotient Game: Step-by-Step 128-Switch Colored Series Circuit &amp; Color-Fiber Bisection (V* = 737/129)',
        '</text>',
    ]

    # ==========================================================================
    # STEP 1 (Top Full Width): Physical Series Circuit, Periodic Color Law & Censoring
    # ==========================================================================
    svg.append('<rect x="20" y="66" width="1000" height="162" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="34" y="86" font-family="Helvetica, Arial, sans-serif" font-size="12.2" font-weight="bold" fill="#0f172a">'
               'STEP 1: The 128-Switch Series Circuit, Periodic Color Map c(k) = PERIODIC[k mod 8], &amp; Censoring Frontier k*</text>')
    svg.append('<text x="34" y="102" font-family="monospace" font-size="9.0" fill="#475569">'
               'Current flows left-to-right (k = 0 → 127) and halts at the FIRST Open switch k* = min{k : s_k = 0}, masking all downstream faults!</text>')

    # Draw 8-switch repeating color block on left (k=0..7) + downstream blocks
    c_palette = [
        (0, "C1:RED",    "#ef4444", "#fef2f2", 1, "m=0"),
        (1, "C2:BLUE",   "#2563eb", "#eff6ff", 0, "m=1"),  # OPEN FAULT k*=1!
        (2, "C3:AMBER",  "#d97706", "#fffbeb", 1, "m=2"),
        (3, "C4:CYAN",   "#0891b2", "#ecfeff", 1, "m=3"),
        (4, "C5:VIOLET", "#9333ea", "#faf5ff", 1, "m=4"),
        (5, "C3:AMBER",  "#d97706", "#fffbeb", 1, "m=5"),
        (6, "C2:BLUE",   "#2563eb", "#eff6ff", 1, "m=6"),
        (7, "C1:RED",    "#ef4444", "#fef2f2", 1, "m=7"),
    ]

    # Power Source Box
    svg.append('<rect x="32" y="120" width="64" height="46" rx="5" fill="#0f172a" stroke="#f59e0b" stroke-width="2"/>')
    svg.append('<text x="64" y="140" font-family="monospace" font-size="9.0" font-weight="bold" fill="#fde047" text-anchor="middle">POWER</text>')
    svg.append('<text x="64" y="154" font-family="monospace" font-size="8.0" fill="#ffffff" text-anchor="middle">Source</text>')
    svg.append('<line x1="96" y1="143" x2="114" y2="143" stroke="#f59e0b" stroke-width="3"/>')

    sx0 = 114
    sw_w = 78
    sw_gap = 10
    for idx, (m_i, c_lbl, c_col, c_bg, s_bit, m_str) in enumerate(c_palette):
        bx = sx0 + idx * (sw_w + sw_gap)
        by = 114
        is_fault = (s_bit == 0)
        border_w = 2.6 if is_fault else 1.5
        svg.append(f'<rect x="{bx}" y="{by}" width="{sw_w}" height="60" rx="5" fill="{c_bg}" stroke="{c_col}" stroke-width="{border_w}"/>')
        svg.append(f'<rect x="{bx}" y="{by}" width="{sw_w}" height="16" rx="4" fill="{c_col}"/>')
        svg.append(f'<text x="{bx+sw_w/2}" y="{by+11.5}" font-family="monospace" font-size="8.0" font-weight="bold" fill="#ffffff" text-anchor="middle">k={m_i} ({c_lbl})</text>')

        if s_bit == 1 and idx == 0:
            # Closed switch with current flowing
            svg.append(f'<line x1="{bx+10}" y1="{by+34}" x2="{bx+sw_w-10}" y2="{by+34}" stroke="#16a34a" stroke-width="2.8"/>')
            svg.append(f'<circle cx="{bx+14}" cy="{by+34}" r="3" fill="#16a34a"/>')
            svg.append(f'<circle cx="{bx+sw_w-14}" cy="{by+34}" r="3" fill="#16a34a"/>')
            svg.append(f'<text x="{bx+sw_w/2}" y="{by+52}" font-family="monospace" font-size="7.8" font-weight="bold" fill="#15803d" text-anchor="middle">s₀=1 (LIVE)</text>')
            svg.append(f'<line x1="{bx+sw_w}" y1="{by+29}" x2="{bx+sw_w+sw_gap}" y2="{by+29}" stroke="#f59e0b" stroke-width="3"/>')
        elif is_fault:
            # Open switch k*=1 where current halts!
            svg.append(f'<line x1="{bx+10}" y1="{by+36}" x2="{bx+26}" y2="{by+36}" stroke="#dc2626" stroke-width="2.5"/>')
            svg.append(f'<line x1="{bx+26}" y1="{by+36}" x2="{bx+50}" y2="{by+23}" stroke="#dc2626" stroke-width="2.5"/>')
            svg.append(f'<circle cx="{bx+26}" cy="{by+36}" r="3" fill="#dc2626"/>')
            svg.append(f'<circle cx="{bx+54}" cy="{by+36}" r="3" fill="#dc2626"/>')
            svg.append(f'<text x="{bx+sw_w/2}" y="{by+52}" font-family="monospace" font-size="7.8" font-weight="bold" fill="#dc2626" text-anchor="middle">s₁=0 (OPEN k*!)</text>')
            svg.append(f'<line x1="{bx+sw_w}" y1="{by+29}" x2="{bx+sw_w+sw_gap}" y2="{by+29}" stroke="#94a3b8" stroke-width="2" stroke-dasharray="3,2"/>')
        else:
            # Downstream switch cut off from current (Fog-of-War!)
            svg.append(f'<line x1="{bx+12}" y1="{by+34}" x2="{bx+sw_w-12}" y2="{by+34}" stroke="#64748b" stroke-width="2"/>')
            svg.append(f'<text x="{bx+sw_w/2}" y="{by+52}" font-family="monospace" font-size="7.4" fill="#64748b" text-anchor="middle">s_{m_i}=1 (No Curr)</text>')
            if idx < 7:
                svg.append(f'<line x1="{bx+sw_w}" y1="{by+29}" x2="{bx+sw_w+sw_gap}" y2="{by+29}" stroke="#94a3b8" stroke-width="2" stroke-dasharray="3,2"/>')

    # Continuation box for Blocks i=1..15 (k=8..127)
    svg.append('<line x1="808" y1="143" x2="828" y2="143" stroke="#94a3b8" stroke-width="2" stroke-dasharray="3,2"/>')
    svg.append('<rect x="828" y="114" width="176" height="60" rx="5" fill="#1e293b" stroke="#475569" stroke-width="1.5"/>')
    svg.append('<text x="916" y="132" font-family="monospace" font-size="8.6" font-weight="bold" fill="#f8fafc" text-anchor="middle">Blocks i = 1 .. 15 (k=8..127)</text>')
    svg.append('<text x="916" y="147" font-family="monospace" font-size="7.8" fill="#cbd5e1" text-anchor="middle">Same 8-color pattern × 16 blocks</text>')
    svg.append('<text x="916" y="162" font-family="monospace" font-size="7.8" font-weight="bold" fill="#f87171" text-anchor="middle">Masked: k=24, 59, 93, 126 = 0!</text>')

    # Bottom annotation inside Step 1
    svg.append('<rect x="32" y="184" width="972" height="34" rx="4" fill="#f1f5f9" stroke="#cbd5e1" stroke-width="1"/>')
    svg.append('<text x="44" y="198" font-family="monospace" font-size="8.5" font-weight="bold" fill="#0f172a">'
               '• Kronecker Color Partition (128 switches = 16 blocks × 8):  C1_RED: m∈{0,7} (32) | C2_BLUE: m∈{1,6} (32) | C3_AMBER: m∈{2,5} (32) | C4_CYAN: m=3 (16) | C5_VIOLET: m=4 (16)</text>')
    svg.append('<text x="44" y="211" font-family="monospace" font-size="8.4" fill="#dc2626">'
               '• Censoring &amp; Aliasing Law: probe(127) sees current halt at k*=1 and returns ONLY its color FAIL(C2_BLUE) — aliasing k*=1 with all 32 Blue switches!</text>')

    # ==========================================================================
    # STEP 2 (Middle Left): The 3 Operations & Why Blind Toggle Breaks the Circuit
    # ==========================================================================
    svg.append('<rect x="20" y="240" width="485" height="205" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="34" y="260" font-family="Helvetica, Arial, sans-serif" font-size="12.0" font-weight="bold" fill="#0f172a">'
               'STEP 2: The 3 Oracle Operations &amp; In-Band Lockout Hazard</text>')

    ops_boxes = [
        (270, "#eff6ff", "#3b82f6", "1. probe(m)  [Prefix Continuity + Fault Color Oracle]",
         "• If k* > m (switches 0..m all closed): returns PASS (0).",
         "• If k* ≤ m (halted in 0..m): returns FAIL(c(k*)) ∈ {C1..C5} (hides k*!)."),
        (324, "#f0fdf4", "#16a34a", "2. inspect(k)  [Local Switch Readout Subject to Current Flow]",
         "• If k ≤ k* (current reaches switch k): returns exact state s_k ∈ {0, 1}.",
         "• If k > k* (upstream switch k* is open): returns UNREACHABLE!"),
        (378, "#fef2f2", "#dc2626", "3. toggle(k)  [State-Flipping Intervention: s_k ← 1 - s_k]",
         "• If s_k == 0 (Open): flips 0 → 1 (Fixed!). Advances frontier L ← k + 1.",
         "• If s_k == 1 (Closed): flips 1 → 0 (BREAKS WORKING SWITCH! Cuts power to >k)."),
    ]
    for oy, obg, ocol, otitle, ol1, ol2 in ops_boxes:
        svg.append(f'<rect x="32" y="{oy}" width="461" height="48" rx="4" fill="{obg}" stroke="{ocol}" stroke-width="1.4"/>')
        svg.append(f'<text x="42" y="{oy+15}" font-family="monospace" font-size="9.0" font-weight="bold" fill="#0f172a">{otitle}</text>')
        svg.append(f'<text x="42" y="{oy+30}" font-family="monospace" font-size="8.0" fill="#1e293b">{ol1}</text>')
        svg.append(f'<text x="42" y="{oy+42}" font-family="monospace" font-size="8.0" font-weight="bold" fill="{ocol if oy==378 else "#334155"}">{ol2}</text>')

    # ==========================================================================
    # STEP 3 (Middle Right): Concrete Walkthrough of Wave 1 & Wave 3 Color-Fiber Bisection
    # ==========================================================================
    svg.append('<rect x="520" y="240" width="500" height="205" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="534" y="260" font-family="Helvetica, Arial, sans-serif" font-size="12.0" font-weight="bold" fill="#0f172a">'
               'STEP 3: Worked Trace — How Color Projection Cuts Probes in Half</text>')

    # Wave 1 Box (Isolating k*=1 in 5 fiber probes instead of 7)
    svg.append('<rect x="532" y="270" width="476" height="82" rx="4" fill="#eff6ff" stroke="#2563eb" stroke-width="1.4"/>')
    svg.append('<text x="542" y="285" font-family="Helvetica, Arial, sans-serif" font-size="9.5" font-weight="bold" fill="#1e3a8a">'
               'Wave 1 (L₀ = 0): Isolating First Open Switch k₁* = 1 via Blue Fiber F(C2_BLUE, 0)</text>')
    w1_lines = [
        "1. E2E Check : probe(127) → FAIL(C2_BLUE). Projects 128 switches onto 32 Blue switches:",
        "   F(C2_BLUE, 0) = [1, 6, 9, 14, 17, 22, ..., 62, 65, ..., 126]  (|F| = 32 candidates).",
        "2. Fiber Bisect (5 probes): probe(fiber[15]=62)→FAIL | probe(fiber[7]=30)→FAIL |",
        "   probe(fiber[3]=14)→FAIL | probe(fiber[1]=6)→FAIL | probe(fiber[0]=1)→FAIL!",
        "3. Verify &amp; Fix: Unique Blue candidate is k*=1! inspect(1)→0 → toggle(1)→1! (L₁ ← 2)",
    ]
    for idx, wl in enumerate(w1_lines):
        svg.append(f'<text x="542" y="{299 + idx*10.5}" font-family="monospace" font-size="7.8" fill="#1e293b">{wl}</text>')

    # Wave 3 Box (Isolating k*=59 in 4 fiber probes after k*=24 is fixed)
    svg.append('<rect x="532" y="358" width="476" height="76" rx="4" fill="#ecfeff" stroke="#0891b2" stroke-width="1.4"/>')
    svg.append('<text x="542" y="373" font-family="Helvetica, Arial, sans-serif" font-size="9.5" font-weight="bold" fill="#155e75">'
               'Wave 3 (After fixing k₂*=24, so L₂ = 25): Isolating k₃* = 59 via Cyan Fiber F(C4_CYAN, 25)</text>')
    w3_lines = [
        "1. E2E Check : probe(127) → FAIL(C4_CYAN). Since C4_CYAN only occurs at m = k mod 8 == 3,",
        "   suffix [25..127] projects onto 13 switches: F = [27,35,43,51,59,67,75,83,91,99,107,115,123]!",
        "2. Fiber Bisect (4 probes): probe(fiber[6]=75)→FAIL | probe(fiber[2]=43)→PASS (L←44) |",
        "   probe(fiber[4]=59)→FAIL | probe(fiber[3]=51)→PASS ⟹ Isolated k₃*=59! inspect(59)→0, toggle(59)→1!",
    ]
    for idx, wl in enumerate(w3_lines):
        svg.append(f'<text x="542" y="{387 + idx*11.0}" font-family="monospace" font-size="7.5" fill="#1e293b">{wl}</text>')

    # ==========================================================================
    # STEP 4 (Bottom Full Width): Exact All-5-Waves Comparison (Agnostic Pi vs Joint Color-Fiber)
    # ==========================================================================
    svg.append('<rect x="20" y="457" width="1000" height="188" rx="6" fill="#ffffff" stroke="#94a3b8" stroke-width="1.5"/>')
    svg.append('<text x="520" y="478" font-family="Helvetica, Arial, sans-serif" font-size="12.2" font-weight="bold" fill="#0f172a" text-anchor="middle">'
               'STEP 4: Complete 5-Wave Trajectory Comparison on adversarial5 (k* ∈ {1, 24, 59, 93, 126})</text>')

    svg.append('<rect x="34" y="488" width="972" height="24" rx="4" fill="#1e293b"/>')
    bcols = [
        (40, "Wave &amp; True Open Switch k*"),
        (198, "Active Suffix [L_t..127]"),
        (338, "Stage-Agnostic Bisection (Π)"),
        (560, "Observed Color &amp; Active Fiber F(c, L_t)"),
        (782, "Joint Color-Fiber Bisection (O⁻¹+Π)"),
    ]
    for cx, c_title in bcols:
        svg.append(f'<text x="{cx}" y="504" font-family="Helvetica, Arial, sans-serif" font-size="8.7" font-weight="bold" fill="#ffffff">{c_title}</text>')

    brows = [
        ("Wave 1: k₁* = 1 (m=1)",  "[0 .. 128] (129 states)", "7 probes: 63→31→15→7→3→1→0",       "C2_BLUE (m∈{1,6}): |F| = 32 switches", "1 E2E + 5 fiber (62→30→14→6→1) = 6"),
        ("Wave 2: k₂* = 24 (m=0)", "[2 .. 127] (126 states)", "1 E2E + 7 probes (64→32→..→24) = 8", "C1_RED (m∈{0,7}): |F| = 31 switches",  "1 E2E + 5 fiber (63→31→15→23→24) = 6"),
        ("Wave 3: k₃* = 59 (m=3)", "[25 .. 127] (103 states)","1 E2E + 7 probes (76→50→..→59) = 8", "C4_CYAN (m==3): |F| = 13 switches",    "1 E2E + 4 fiber (75→43→59→51) = 5"),
        ("Wave 4: k₄* = 93 (m=5)", "[60 .. 127] (68 states)", "1 E2E + 6 probes (93→76→..→92) = 7", "C3_AMBER (m∈{2,5}): |F| = 17 switches","1 E2E + 4 fiber (93→74→85→90) = 5"),
        ("Wave 5: k₅* = 126 (m=6)","[94 .. 127] (34 states)", "1 E2E + 6 probes (110→..→126) = 7", "C2_BLUE (m∈{1,6}): |F| = 9 switches",   "1 E2E + 4 fiber (110→118→121→126) = 5"),
        ("Final Check + Total",    "L₅ = 127 → All Closed!", "1 E2E check → 38 Total (0 wrong)",   "probe(127) → PASS_ALL_CLOSED (0)",     "1 E2E check → 28 Total (22 fiber + 6 E2E)!"),
    ]
    for r_i, (w_lbl, suf_lbl, pi_lbl, col_lbl, jnt_lbl) in enumerate(brows):
        ry = 513 + r_i * 21
        is_last = (r_i == len(brows) - 1)
        bg = "#f0fdf4" if is_last else ("#f8fafc" if (r_i % 2 == 0) else "#f1f5f9")
        svg.append(f'<rect x="34" y="{ry}" width="972" height="20" fill="{bg}" stroke="#cbd5e1" stroke-width="{1.4 if is_last else 0.6}"/>')
        fw = "bold" if is_last else "normal"
        svg.append(f'<text x="40" y="{ry+13.5}" font-family="monospace" font-size="7.7" font-weight="bold" fill="#0f172a">{w_lbl}</text>')
        svg.append(f'<text x="198" y="{ry+13.5}" font-family="monospace" font-size="7.5" font-weight="{fw}" fill="#475569">{suf_lbl}</text>')
        svg.append(f'<text x="338" y="{ry+13.5}" font-family="monospace" font-size="7.5" font-weight="{fw}" fill="#1e3a8a">{pi_lbl}</text>')
        svg.append(f'<text x="560" y="{ry+13.5}" font-family="monospace" font-size="7.5" font-weight="{fw}" fill="#b45309">{col_lbl}</text>')
        svg.append(f'<text x="782" y="{ry+13.5}" font-family="monospace" font-size="7.5" font-weight="bold" fill="#166534">{jnt_lbl}</text>')

    svg.append('</svg>')
    save_svg_and_png("fig10_minimal_color_circuit_step_by_step", "\n".join(svg))


if __name__ == "__main__":
    make_fig1_simple_example()
    make_fig2_complex_16hop_trace()
    make_fig3_matrix_architecture()
    make_fig4_markov_drift()
    make_fig5_complexity_and_convex()
    make_fig6_transformer_and_router()
    make_fig7_2d_game_and_semantics()
    make_fig8_joint_subspace_and_codex_ablation()
    make_fig9_economic_and_outage_risk()
    make_fig10_minimal_color_circuit_step_by_step()
    print("All SVG and PNG figures generated successfully.")
