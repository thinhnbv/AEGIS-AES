#!/usr/bin/env python3
"""
Render AEGIS-AES Architecture diagram using matplotlib.
Outputs: fig1_aegis_architecture.png (300 DPI)
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import matplotlib.patheffects as pe
import numpy as np

# ── Figure setup ──────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(16, 11), dpi=100)
ax.set_xlim(0, 16)
ax.set_ylim(0, 11)
ax.axis('off')
fig.patch.set_facecolor('white')

# ── Color palette ──────────────────────────────────────────────
C = {
    'wrapper':  '#4A90E2',
    'core':    '#7F8C8D',
    'klg':     '#5CBC5C',
    'fic':     '#EC971F',
    'rcm':     '#9B59B6',
    'red':     '#1ABC9C',
    'orc':     '#EC971F',
    'tru':     '#D9534F',
    'io':      '#ECF0F1',
    'sec_out': '#FADAD5',
    'arrow':   '#555555',
    'text':    '#2C3E50',
    'legend':  '#F8F9FA',
    'grid':    '#BDC3C7',
}

def shadow(color='#00000030'):
    return [pe.withSimplePatchShadow(offset=(2, -2), shadow_rgbFace=color, alpha=0.3)]

def rounded_box(ax, x, y, w, h, color, text, sub='', fontsize=9,
                text_color='white', label='', label_color='white', bold=False):
    """Draw a rounded rectangle with text."""
    rect = FancyBboxPatch((x, y), w, h,
                          boxstyle="round,pad=0.08",
                          facecolor=color, edgecolor='white',
                          linewidth=1.5, zorder=3)
    ax.add_patch(rect)

    weight = 'bold' if bold else 'normal'
    lines = text.split('\n')
    total_h = len(lines) * fontsize * 1.3
    start_y = y + h/2 + total_h/2 - fontsize * 1.1

    for i, line in enumerate(lines):
        ax.text(x + w/2, start_y - i * fontsize * 1.4, line,
                ha='center', va='center', fontsize=fontsize,
                fontweight=weight, color=text_color,
                zorder=4, linespacing=1.3)
    if sub:
        ax.text(x + w/2, y + 4, sub,
                ha='center', va='center', fontsize=7,
                color='white', style='italic', alpha=0.75, zorder=4)

    if label:
        ax.text(x + w/2, y - 3.5, label,
                ha='center', va='top', fontsize=7,
                color=label_color, fontweight='bold', zorder=4)

    return rect

def io_box(ax, x, y, w, h, text, fontsize=8.5):
    """Input / output box."""
    rect = FancyBboxPatch((x, y), w, h,
                          boxstyle="round,pad=0.05",
                          facecolor=C['io'], edgecolor='#95A5A6',
                          linewidth=1, zorder=3)
    ax.add_patch(rect)
    lines = text.split('\n')
    start_y = y + h/2 + (len(lines)-1) * fontsize * 0.6
    for i, line in enumerate(lines):
        ax.text(x + w/2, start_y - i * fontsize * 1.3, line,
                ha='center', va='center', fontsize=fontsize,
                color=C['text'], zorder=4, linespacing=1.3)

def arrow(ax, x1, y1, x2, y2, color='#555', lw=1.5, style='-'):
    """Simple arrow."""
    ls = '--' if style == '--' else '-'
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle='-|>',
                                color=color, lw=lw,
                                linestyle=ls,
                                shrinkA=3, shrinkB=3),
                zorder=5)

def elbow_arrow(ax, x1, y1, x2, y2, color='#555', lw=1.5, style='-',
                label='', label_side='top'):
    """L-shaped elbow arrow."""
    ls = '--' if style == '--' else '-'
    # Horizontal segment
    ax.plot([x1, x2], [y1, y1], color=color, lw=lw,
            linestyle=ls, zorder=5, solid_capstyle='round')
    # Vertical segment
    ax.plot([x2, x2], [y1, y2], color=color, lw=lw,
            linestyle=ls, zorder=5, solid_capstyle='round')
    # Arrow head on vertical segment
    if y2 < y1:
        ax.annotate('', xy=(x2, y2), xytext=(x2, y2 + 0.15),
                    arrowprops=dict(arrowstyle='-|>', color=color, lw=lw),
                    zorder=6)
    else:
        ax.annotate('', xy=(x2, y2), xytext=(x2, y2 - 0.15),
                    arrowprops=dict(arrowstyle='-|>', color=color, lw=lw),
                    zorder=6)
    if label:
        mx = (x1 + x2) / 2
        my = y1 + 0.15 if label_side == 'top' else y1 - 0.25
        ax.text(mx, my, label, ha='center', va='center',
                fontsize=7, color=color, fontweight='bold', zorder=6)

# ════════════════════════════════════════════════════════════════
#  LAYOUT POSITIONS (all in figure units 0-16 x 0-11)
# ════════════════════════════════════════════════════════════════

TITLE_Y   = 10.6
WRAPPER_X, WRAPPER_Y = 4.8, 8.3
WRAPPER_W, WRAPPER_H = 3.5, 0.75

CORE_X, CORE_Y = 8.5, 6.5
CORE_W, CORE_H = 2.5, 1.8

# Security modules (left column)
KLG_X, KLG_Y = 1.1, 5.4
KLG_W, KLG_H = 2.0, 1.4
FIC_X, FIC_Y = 1.1, 3.85
FIC_W, FIC_H = 2.0, 1.1
RCM_X, RCM_Y = 1.1, 2.3
RCM_W, RCM_H = 2.0, 1.1
RED_X, RED_Y = 1.1, 0.8
RED_W, RED_H = 2.0, 1.1

# ORC (right of core)
ORC_X, ORC_Y = 11.7, 6.5
ORC_W, ORC_H = 2.0, 1.3

# TRU (center-bottom)
TRU_X, TRU_Y = 6.1, 4.0
TRU_W, TRU_H = 4.8, 2.2

# Outputs
OUT_DATA_X, OUT_DATA_Y = 8.5, 9.5
OUT_DATA_W, OUT_DATA_H = 2.5, 0.6
OUT_SEC_X, OUT_SEC_Y = 12.0, 4.7
OUT_SEC_W, OUT_SEC_H = 2.2, 0.65

# Inputs
IN_KEY_X, IN_KEY_Y = 0.8, 8.5
IN_KEY_W, IN_KEY_H = 2.2, 0.6
IN_DATA_X, IN_DATA_Y = 0.8, 7.7
IN_DATA_W, IN_DATA_H = 2.2, 0.6
IN_CLK_X, IN_CLK_Y = 0.8, 7.0
IN_CLK_W, IN_CLK_H = 2.2, 0.45

# ════════════════════════════════════════════════════════════════
#  TITLE
# ════════════════════════════════════════════════════════════════
ax.text(8, TITLE_Y, 'Hình 1. Kiến trúc tổng thể AEGIS-AES',
        ha='center', va='center', fontsize=17, fontweight='bold',
        color=C['text'], zorder=4)

# ════════════════════════════════════════════════════════════════
#  INPUT BLOCKS
# ════════════════════════════════════════════════════════════════
io_box(ax, IN_KEY_X, IN_KEY_Y, IN_KEY_W, IN_KEY_H, 'Key input\n(nạp khóa)')
io_box(ax, IN_DATA_X, IN_DATA_Y, IN_DATA_W, IN_DATA_H, 'Data input\n(plaintext/ciphertext)')
io_box(ax, IN_CLK_X, IN_CLK_Y, IN_CLK_W, IN_CLK_H, 'clk, rst_n')

# ════════════════════════════════════════════════════════════════
#  TOP WRAPPER
# ════════════════════════════════════════════════════════════════
r = FancyBboxPatch((WRAPPER_X, WRAPPER_Y), WRAPPER_W, WRAPPER_H,
                    boxstyle="round,pad=0.1",
                    facecolor=C['wrapper'], edgecolor='white',
                    linewidth=2, zorder=3)
ax.add_patch(r)
ax.text(WRAPPER_X + WRAPPER_W/2, WRAPPER_Y + WRAPPER_H*0.65,
        'aegis_aes_top.v', ha='center', va='center',
        fontsize=10, fontweight='bold', color='white', zorder=4)
ax.text(WRAPPER_X + WRAPPER_W/2, WRAPPER_Y + WRAPPER_H*0.3,
        '(6-state FSM wrapper · EN\_ORC)', ha='center', va='center',
        fontsize=7.5, color='white', alpha=0.9, zorder=4)

# ════════════════════════════════════════════════════════════════
#  AES CORE
# ════════════════════════════════════════════════════════════════
r = FancyBboxPatch((CORE_X, CORE_Y), CORE_W, CORE_H,
                    boxstyle="round,pad=0.1",
                    facecolor=C['core'], edgecolor='#444',
                    linewidth=1.5, zorder=3)
ax.add_patch(r)
ax.text(CORE_X + CORE_W/2, CORE_Y + CORE_H*0.78,
        'AES Core', ha='center', va='center',
        fontsize=10, fontweight='bold', color='white', zorder=4)
ax.text(CORE_X + CORE_W/2, CORE_Y + CORE_H*0.55,
        'secworks/aes (golden)', ha='center', va='center',
        fontsize=7, color='white', alpha=0.7, style='italic', zorder=4)
ax.plot([CORE_X + 0.15, CORE_X + CORE_W - 0.15],
        [CORE_Y + CORE_H*0.42, CORE_Y + CORE_H*0.42],
        color='white', lw=0.6, alpha=0.4, zorder=4)
ax.text(CORE_X + CORE_W/2, CORE_Y + CORE_H*0.3,
        'Kết quả mã hóa/giải mã', ha='center', va='center',
        fontsize=7.5, color='white', zorder=4)
ax.text(CORE_X + CORE_W/2, CORE_Y + CORE_H*0.15,
        '(không hiển thị bit-width)', ha='center', va='center',
        fontsize=6.5, color='white', alpha=0.65, zorder=4)

# ════════════════════════════════════════════════════════════════
#  SECURITY MODULES — KLG, FIC, RCM, RED
# ════════════════════════════════════════════════════════════════
rounded_box(ax, KLG_X, KLG_Y, KLG_W, KLG_H, C['klg'],
            'KLG\nKey-Leak Guard',
            'P1', fontsize=9, label_color='white')
ax.plot([KLG_X + 0.15, KLG_X + KLG_W - 0.15],
        [KLG_Y + 0.45, KLG_Y + 0.45],
        color='white', lw=0.6, alpha=0.35, zorder=4)
ax.text(KLG_X + KLG_W/2, KLG_Y + 0.3, 'Phát hiện rò rỉ khóa',
        ha='center', va='center', fontsize=6.5, color='white', zorder=4)
ax.text(KLG_X + KLG_W/2, KLG_Y + 0.15, '(3 tier kiểm tra)',
        ha='center', va='center', fontsize=6, color='white', alpha=0.7, zorder=4)

rounded_box(ax, FIC_X, FIC_Y, FIC_W, FIC_H, C['fic'],
            'FIC\nFSM Integrity Checker',
            'P4', fontsize=9, label_color='white')
ax.plot([FIC_X + 0.15, FIC_X + FIC_W - 0.15],
        [FIC_Y + 0.38, FIC_Y + 0.38],
        color='white', lw=0.6, alpha=0.35, zorder=4)
ax.text(FIC_X + FIC_W/2, FIC_Y + 0.22, 'Kiểm tra tính toàn vẹn FSM',
        ha='center', va='center', fontsize=6.5, color='white', zorder=4)

rounded_box(ax, RCM_X, RCM_Y, RCM_W, RCM_H, C['rcm'],
            'RCM\nRound Consistency Monitor',
            'P3', fontsize=9, label_color='white')
ax.plot([RCM_X + 0.15, RCM_X + RCM_W - 0.15],
        [RCM_Y + 0.38, RCM_Y + 0.38],
        color='white', lw=0.6, alpha=0.35, zorder=4)
ax.text(RCM_X + RCM_W/2, RCM_Y + 0.22, 'Giám sát số vòng AES',
        ha='center', va='center', fontsize=6.5, color='white', zorder=4)

rounded_box(ax, RED_X, RED_Y, RED_W, RED_H, C['red'],
            'RED\nRare-Event Detector',
            'T1/T2/T3', fontsize=9, label_color='white')
ax.plot([RED_X + 0.15, RED_X + RED_W - 0.15],
        [RED_Y + 0.38, RED_Y + 0.38],
        color='white', lw=0.6, alpha=0.35, zorder=4)
ax.text(RED_X + RED_W/2, RED_Y + 0.22, 'Phát hiện sự kiện hiếm',
        ha='center', va='center', fontsize=6.5, color='white', zorder=4)

# ════════════════════════════════════════════════════════════════
#  ORC
# ════════════════════════════════════════════════════════════════
rounded_box(ax, ORC_X, ORC_Y, ORC_W, ORC_H, C['orc'],
            'ORC\nOutput Redundancy Checker',
            'P2', fontsize=9, label_color='white')
ax.plot([ORC_X + 0.15, ORC_X + ORC_W - 0.15],
        [ORC_Y + 0.4, ORC_Y + 0.4],
        color='white', lw=0.6, alpha=0.35, zorder=4)
ax.text(ORC_X + ORC_W/2, ORC_Y + 0.25, 'Kiểm tra dư thừa đầu ra',
        ha='center', va='center', fontsize=6.5, color='white', zorder=4)
ax.text(ORC_X + ORC_W/2, ORC_Y + 0.1, '(nhân bản SubBytes-ShiftRows-ARK)',
        ha='center', va='center', fontsize=5.5, color='white', alpha=0.7, zorder=4)

# ════════════════════════════════════════════════════════════════
#  TRU
# ════════════════════════════════════════════════════════════════
r = FancyBboxPatch((TRU_X, TRU_Y), TRU_W, TRU_H,
                    boxstyle="round,pad=0.12",
                    facecolor=C['tru'], edgecolor='white',
                    linewidth=2.5, zorder=3)
ax.add_patch(r)
ax.text(TRU_X + TRU_W/2, TRU_Y + TRU_H*0.9,
        'TRU — Tamper Response Unit',
        ha='center', va='center', fontsize=10, fontweight='bold',
        color='white', zorder=4)
ax.plot([TRU_X + 0.2, TRU_X + TRU_W - 0.2],
        [TRU_Y + TRU_H*0.76, TRU_Y + TRU_H*0.76],
        color='white', lw=0.7, alpha=0.4, zorder=4)
ax.text(TRU_X + TRU_W/2, TRU_Y + TRU_H*0.64,
        'FSM 3 trạng thái',
        ha='center', va='center', fontsize=8.5, color='white', zorder=4)
ax.text(TRU_X + TRU_W/2, TRU_Y + TRU_H*0.52,
        '(State-A → State-B → State-C)',
        ha='center', va='center', fontsize=7.5, color='white', alpha=0.85, zorder=4)
ax.plot([TRU_X + 0.2, TRU_X + TRU_W - 0.2],
        [TRU_Y + TRU_H*0.43, TRU_Y + TRU_H*0.43],
        color='white', lw=0.7, alpha=0.4, zorder=4)
ax.text(TRU_X + TRU_W/2, TRU_Y + TRU_H*0.32,
        'Khóa bảo vệ: secure\_reset · block\_output',
        ha='center', va='center', fontsize=7.5, color='white', zorder=4)
ax.text(TRU_X + TRU_W/2, TRU_Y + TRU_H*0.15,
        'Đề xuất',
        ha='center', va='center', fontsize=7, color='#FFAAAA',
        fontweight='bold', style='italic', zorder=4)

# ════════════════════════════════════════════════════════════════
#  OUTPUTS
# ════════════════════════════════════════════════════════════════
io_box(ax, OUT_DATA_X, OUT_DATA_Y, OUT_DATA_W, OUT_DATA_H,
       'Data output\n(ciphertext/plaintext)')
r = FancyBboxPatch((OUT_SEC_X, OUT_SEC_Y), OUT_SEC_W, OUT_SEC_H,
                    boxstyle="round,pad=0.05",
                    facecolor=C['sec_out'], edgecolor=C['tru'],
                    linewidth=1.5, zorder=3)
ax.add_patch(r)
ax.text(OUT_SEC_X + OUT_SEC_W/2, OUT_SEC_Y + OUT_SEC_H*0.72,
        'Security status output',
        ha='center', va='center', fontsize=7.5, color=C['tru'],
        fontweight='bold', zorder=4)
ax.text(OUT_SEC_X + OUT_SEC_W/2, OUT_SEC_Y + OUT_SEC_H*0.28,
        '(alarm\_out · warn\_out)',
        ha='center', va='center', fontsize=6.5, color='#922B21', zorder=4)

# ════════════════════════════════════════════════════════════════
#  ARROWS
# ════════════════════════════════════════════════════════════════

# Inputs → Wrapper
arrow(ax, IN_KEY_X+IN_KEY_W, IN_KEY_Y+IN_KEY_H/2,
          WRAPPER_X, WRAPPER_Y+WRAPPER_H/2)
arrow(ax, IN_DATA_X+IN_DATA_W, IN_DATA_Y+IN_DATA_H/2,
          WRAPPER_X, WRAPPER_Y+WRAPPER_H*0.6)
arrow(ax, IN_CLK_X+IN_CLK_W, IN_CLK_Y+IN_CLK_H/2,
          WRAPPER_X, WRAPPER_Y+WRAPPER_H*0.35)

# Wrapper → Core (dashed = control)
ax.annotate('', xy=(CORE_X, CORE_Y+CORE_H/2),
            xytext=(WRAPPER_X+WRAPPER_W, WRAPPER_Y),
            arrowprops=dict(arrowstyle='-|>', color=C['arrow'],
                            lw=1.5, linestyle='--',
                            shrinkA=3, shrinkB=3), zorder=5)
ax.text(WRAPPER_X+WRAPPER_W+0.25, WRAPPER_Y+0.6,
        'control\nsignals', ha='left', va='center',
        fontsize=7, color='#7F8C8D', zorder=6)

# Core → KLG
arrow(ax, CORE_X, CORE_Y+CORE_H*0.5, KLG_X+KLG_W, KLG_Y+KLG_H*0.5)
ax.text(CORE_X-0.5, CORE_Y+CORE_H*0.58, 'output',
        ha='right', va='center', fontsize=7, color='#7F8C8D', zorder=6)

# Core → FIC (dashed)
ax.annotate('', xy=(FIC_X+FIC_W, FIC_Y+FIC_H/2),
            xytext=(CORE_X, CORE_Y+CORE_H*0.28),
            arrowprops=dict(arrowstyle='-|>', color=C['arrow'],
                            lw=1.2, linestyle='--',
                            shrinkA=3, shrinkB=3), zorder=5)
ax.text(CORE_X-0.5, CORE_Y+CORE_H*0.32, 'internal state',
        ha='right', va='center', fontsize=7, color='#7F8C8D', zorder=6)

# Core → RCM
arrow(ax, CORE_X, CORE_Y+CORE_H*0.15, RCM_X+RCM_W, RCM_Y+RCM_H*0.5)
ax.text(CORE_X-0.5, CORE_Y+CORE_H*0.1, 'round count',
        ha='right', va='center', fontsize=7, color='#7F8C8D', zorder=6)

# Core → ORC
arrow(ax, CORE_X+CORE_W, CORE_Y+CORE_H*0.55, ORC_X, ORC_Y+ORC_H*0.5)
ax.text(CORE_X+CORE_W+0.2, CORE_Y+CORE_H*0.62, 'output',
        ha='left', va='center', fontsize=7, color='#7F8C8D', zorder=6)

# KLG → TRU (alarm_P1)
ax.plot([KLG_X+KLG_W, TRU_X], [KLG_Y+KLG_H/2, KLG_Y+KLG_H/2],
        color=C['klg'], lw=2, zorder=5)
ax.annotate('', xy=(TRU_X, TRU_Y+TRU_H*0.72),
            xytext=(TRU_X-0.15, KLG_Y+KLG_H/2),
            arrowprops=dict(arrowstyle='-|>', color=C['klg'],
                            lw=2, shrinkA=0, shrinkB=5), zorder=6)
ax.text((KLG_X+KLG_W+TRU_X)/2, KLG_Y+KLG_H/2+0.15,
        'alarm\_P1', ha='center', va='bottom',
        fontsize=8, fontweight='bold', color=C['klg'], zorder=7)

# FIC → TRU (alarm_P4)
ax.plot([FIC_X+FIC_W, TRU_X], [FIC_Y+FIC_H/2, FIC_Y+FIC_H/2],
        color=C['fic'], lw=2, zorder=5)
ax.annotate('', xy=(TRU_X, TRU_Y+TRU_H*0.56),
            xytext=(TRU_X-0.15, FIC_Y+FIC_H/2),
            arrowprops=dict(arrowstyle='-|>', color=C['fic'],
                            lw=2, shrinkA=0, shrinkB=5), zorder=6)
ax.text((FIC_X+FIC_W+TRU_X)/2, FIC_Y+FIC_H/2+0.15,
        'alarm\_P4', ha='center', va='bottom',
        fontsize=8, fontweight='bold', color=C['fic'], zorder=7)

# RCM → TRU (alarm_P3)
ax.plot([RCM_X+RCM_W, TRU_X], [RCM_Y+RCM_H/2, RCM_Y+RCM_H/2],
        color=C['rcm'], lw=2, zorder=5)
ax.annotate('', xy=(TRU_X, TRU_Y+TRU_H*0.4),
            xytext=(TRU_X-0.15, RCM_Y+RCM_H/2),
            arrowprops=dict(arrowstyle='-|>', color=C['rcm'],
                            lw=2, shrinkA=0, shrinkB=5), zorder=6)
ax.text((RCM_X+RCM_W+TRU_X)/2, RCM_Y+RCM_H/2+0.15,
        'alarm\_P3', ha='center', va='bottom',
        fontsize=8, fontweight='bold', color=C['rcm'], zorder=7)

# RED → TRU (warning_Tx)
ax.plot([RED_X+RED_W, TRU_X], [RED_Y+RED_H/2, RED_Y+RED_H/2],
        color=C['red'], lw=2, zorder=5)
ax.annotate('', xy=(TRU_X, TRU_Y+TRU_H*0.24),
            xytext=(TRU_X-0.15, RED_Y+RED_H/2),
            arrowprops=dict(arrowstyle='-|>', color=C['red'],
                            lw=2, shrinkA=0, shrinkB=5), zorder=6)
ax.text((RED_X+RED_W+TRU_X)/2, RED_Y+RED_H/2+0.15,
        'warning\_Tx', ha='center', va='bottom',
        fontsize=8, fontweight='bold', color=C['red'], zorder=7)

# ORC → TRU (alarm_P2)
ax.plot([ORC_X, TRU_X+TRU_W], [ORC_Y+ORC_H/2, ORC_Y+ORC_H/2],
        color=C['orc'], lw=2, zorder=5)
ax.annotate('', xy=(TRU_X+TRU_W, TRU_Y+TRU_H*0.4),
            xytext=(TRU_X+TRU_W+0.15, ORC_Y+ORC_H/2),
            arrowprops=dict(arrowstyle='-|>', color=C['orc'],
                            lw=2, shrinkA=0, shrinkB=5), zorder=6)
ax.text((ORC_X+TRU_X+TRU_W)/2, ORC_Y+ORC_H/2+0.15,
        'alarm\_P2', ha='center', va='bottom',
        fontsize=8, fontweight='bold', color=C['orc'], zorder=7)

# TRU → Core (secure_reset, dashed red)
# Elbow: TRU top → up → right → Core
tru_top_y = TRU_Y + TRU_H
ax.plot([TRU_X+TRU_W/2, TRU_X+TRU_W/2], [tru_top_y, tru_top_y+0.4],
        color=C['tru'], lw=2, linestyle='--', zorder=5)
ax.plot([TRU_X+TRU_W/2, CORE_X+CORE_W/2], [tru_top_y+0.4, tru_top_y+0.4],
        color=C['tru'], lw=2, linestyle='--', zorder=5)
ax.annotate('', xy=(CORE_X+CORE_W/2, CORE_Y+CORE_H+0.05),
            xytext=(CORE_X+CORE_W/2, tru_top_y+0.4),
            arrowprops=dict(arrowstyle='-|>', color=C['tru'],
                            lw=2, linestyle='--'), zorder=6)
ax.text(TRU_X+TRU_W/2+0.3, tru_top_y+0.25,
        'secure\_reset', ha='left', va='center',
        fontsize=8, fontweight='bold', color=C['tru'], zorder=7)

# Core → Data output (dashed)
ax.annotate('', xy=(OUT_DATA_X+OUT_DATA_W/2, OUT_DATA_Y+OUT_DATA_H),
            xytext=(CORE_X+CORE_W/2, CORE_Y+CORE_H),
            arrowprops=dict(arrowstyle='-|>', color=C['arrow'],
                            lw=1.5, linestyle='--',
                            shrinkA=3, shrinkB=3), zorder=5)

# TRU → Security output (dashed)
ax.plot([TRU_X+TRU_W, OUT_SEC_X], [TRU_Y+TRU_H/2, TRU_Y+TRU_H/2],
        color=C['arrow'], lw=1.5, linestyle='--', zorder=5)
ax.annotate('', xy=(OUT_SEC_X, OUT_SEC_Y+OUT_SEC_H/2),
            xytext=(TRU_X+TRU_W, TRU_Y+TRU_H/2),
            arrowprops=dict(arrowstyle='-|>', color=C['arrow'],
                            lw=1.5, linestyle='--',
                            shrinkA=3, shrinkB=3), zorder=6)

# ════════════════════════════════════════════════════════════════
#  LEGEND (bottom)
# ════════════════════════════════════════════════════════════════
leg_y = 0.05
leg_h = 0.72
r = FancyBboxPatch((0.3, leg_y), 15.4, leg_h,
                    boxstyle="round,pad=0.1",
                    facecolor=C['legend'], edgecolor=C['grid'],
                    linewidth=1, zorder=2)
ax.add_patch(r)
ax.text(8, leg_y+leg_h-0.12, 'Chú thích · Legend',
        ha='center', va='top', fontsize=9, fontweight='bold',
        color=C['text'], zorder=3)

# Color swatches
swatches = [
    (0.6,  C['wrapper'], 'Wrapper (aegis\_aes\_top.v)'),
    (2.55, C['core'],     'AES Core (golden)'),
    (4.35, C['klg'],      'KLG (P1)'),
    (5.65, C['fic'],      'FIC (P4)'),
    (6.85, C['rcm'],      'RCM (P3)'),
    (7.95, C['red'],      'RED (T1–T3)'),
    (9.1,  C['orc'],      'ORC (P2)'),
    (10.2, C['tru'],      'TRU (Đề xuất)'),
]
for sx, color, label in swatches:
    sw = FancyBboxPatch((sx, leg_y+leg_h-0.4), 0.18, 0.18,
                        boxstyle="round,pad=0.02",
                        facecolor=color, edgecolor='none', zorder=3)
    ax.add_patch(sw)
    ax.text(sx+0.25, leg_y+leg_h-0.31, label,
            ha='left', va='center', fontsize=7.5,
            color=C['text'], zorder=3)

# Line style samples
leg_line_y = leg_y + leg_h - 0.58
ax.plot([0.6, 1.05], [leg_line_y, leg_line_y],
        color=C['arrow'], lw=1.5, zorder=3)
ax.annotate('', xy=(1.05, leg_line_y), xytext=(0.6, leg_line_y),
            arrowprops=dict(arrowstyle='-|>', color=C['arrow'], lw=1.5), zorder=4)
ax.text(1.15, leg_line_y, 'Dòng dữ liệu', va='center',
        fontsize=7, color=C['text'], zorder=3)

ax.plot([2.55, 3.0], [leg_line_y, leg_line_y],
        color=C['arrow'], lw=1.5, linestyle='--', zorder=3)
ax.annotate('', xy=(3.0, leg_line_y), xytext=(2.55, leg_line_y),
            arrowprops=dict(arrowstyle='-|>', color=C['arrow'],
                            lw=1.5, linestyle='--'), zorder=4)
ax.text(3.1, leg_line_y, 'Tín hiệu điều khiển', va='center',
        fontsize=7, color=C['text'], zorder=3)

ax.plot([5.15, 5.6], [leg_line_y, leg_line_y],
        color=C['tru'], lw=2, linestyle='--', zorder=3)
ax.annotate('', xy=(5.6, leg_line_y), xytext=(5.15, leg_line_y),
            arrowprops=dict(arrowstyle='-|>', color=C['tru'],
                            lw=2, linestyle='--'), zorder=4)
ax.text(5.7, leg_line_y, 'secure\_reset', va='center',
        fontsize=7, color=C['text'], zorder=3)

# Alarm signal legend
ax.text(7.2, leg_y+leg_h-0.42,
        'alarm\_P1/P2/P3/P4 = alarm từ KLG/ORC/RCM/FIC',
        ha='left', va='center', fontsize=7, color='#7F8C8D', zorder=3)
ax.text(7.2, leg_y+leg_h-0.57,
        'warning\_Tx = cảnh báo từ RED (Tx = Trojan ID)',
        ha='left', va='center', fontsize=7, color='#7F8C8D', zorder=3)

# ════════════════════════════════════════════════════════════════
#  SAVE
# ════════════════════════════════════════════════════════════════
output_path = '/home/thinhnbv/aegis-aes/docs/figures/fig1_aegis_architecture.png'
plt.tight_layout(pad=0.3)
plt.savefig(output_path, dpi=150, bbox_inches='tight',
            facecolor='white', edgecolor='none')
plt.close()
print(f'✅ Saved: {output_path}')
