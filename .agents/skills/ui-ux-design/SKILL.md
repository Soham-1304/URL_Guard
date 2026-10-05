---
name: ui-ux-design
description: |
  Comprehensive standards and guidelines for building world-class, high-craft web applications for machine learning, scientific research, and data products.
  Inspired by modern editorial evidence-based interfaces like Cifra (cifra-salary.vercel.app), Linear, and Stripe Press.
  Enforces typographic hierarchy, curated color palettes, accessible contrasts, scrollytelling, and purposeful micro-interactions.
---

# High-Craft UI/UX Design System for ML & Data Products

This skill governs the visual and experiential design of web applications that present machine learning models, statistical evidence, and interactive diagnostics.

---

## 1. Core Philosophy: "With Evidence"
Machine learning interfaces should not look like toy form submissions. They must establish credibility and trust through **visible proof trails**:
- Every prediction must be accompanied by confidence scores, feature contributions, and dataset context.
- Status badges: Monospace, all-caps, with glowing status pips (e.g. `● LIVE MODEL EVIDENCE`, `CALIBRATED ON 55K TEST SAMPLES`).
- Separation of concerns: High-level executive verdict for general users + deep analytical drill-down for technical review.

---

## 2. Typography System
Pair distinct font classifications to create contrast, editorial weight, and scientific precision:
- **Headings & Statements**: High-contrast Editorial Serif or Geometric Sans (`Instrument Serif`, `Newsreader`, `Geist`, `Plus Jakarta Sans`).
- **Body & Explanations**: Clean, legible Sans-Serif (`Inter`, `Geist Sans`, `-apple-system`).
- **Data Points, Metrics & Code**: Tabular Monospace (`JetBrains Mono`, `Geist Mono`, `IBM Plex Mono`).

### Type Scale:
- **Hero Title**: `clamp(2.5rem, 5vw, 4rem)`, line-height `1.1`, letter-spacing `-0.03em`.
- **Section Headers**: `1.75rem` - `2.25rem`, line-height `1.2`.
- **Eyebrow / Overlines**: `0.75rem` - `0.8125rem`, uppercase, letter-spacing `0.08em`, font-weight `600`, monospace.
- **Card Titles**: `1.125rem`, font-weight `600`.
- **Body**: `0.9375rem` (`15px`) or `1rem` (`16px`), line-height `1.6`.
- **Micro-copy & Captions**: `0.8125rem`, muted color.

---

## 3. Curated Color Palette
Avoid saturated primary colors and generic dark-mode bootstrap defaults. Use warm stone/paper tones with disciplined functional signal colors.

### Base Tokens (Warm Slate / Paper Theme):
- **Page Background (`--bg`)**: `#fafaf9` (Warm Bone / Canvas) or `#0a0b0d` (Dark Obsidian).
- **Surface / Card Background (`--surface`)**: `#ffffff` (Elevated Paper) or `#12151a` (Dark Card).
- **Surface Secondary (`--surface-muted`)**: `#f4f4f2` / `#181c24`.
- **Border / Divider (`--border`)**: `#e5e5e3` (Subtle hairline) / `#222733`.
- **Ink Primary (`--text-primary`)**: `#0d0f12` / `#f3f4f6`.
- **Ink Secondary (`--text-secondary`)**: `#525866` / `#94a3b8`.
- **Ink Muted (`--text-muted`)**: `#868c98` / `#64748b`.

### Semantic Signal Colors:
- **Safe / Benign**: Emerald Green
  - Text: `#059669`
  - Background surface: `#ecfdf5`
  - Border: `#a7f3d0`
- **Threat / Malicious**: Vivid Crimson
  - Text: `#dc2626`
  - Background surface: `#fef2f2`
  - Border: `#fecaca`
- **Evidence / Science**: Deep Cobalt Blue
  - Text: `#1d4ed8`
  - Background surface: `#eff6ff`
  - Border: `#bfdbfe`
- **Anomaly / Warning**: Warm Amber
  - Text: `#b45309`
  - Background surface: `#fffbeb`
  - Border: `#fde68a`

---

## 4. Layout & Information Architecture
A complete narrative interface should follow a logical scrollytelling path:
1. **Header / Navigation**: Sticky, glassmorphic (`backdrop-filter: blur(12px)`), clean brand wordmark, tab navigation, and primary action CTA.
2. **Hero Section**:
   - Eyebrow badge with live pulse indicator.
   - Assertive value proposition (`Malicious URLs detected. With evidence.`).
   - "Live Evidence" preview card demonstrating verified accuracy and latency.
3. **Interactive Scanner (The Tool)**:
   - Floating omnibox input with auto-paste, clear button, and realistic preset examples.
   - Real-time threat meter (SVG radial gauge or segmented gradient meter).
   - Expandable breakdown of the 30 structural/lexical factors.
4. **The Feature Intelligence Matrix**:
   - Permutation importance ranking (explaining *why* `n_dots` is #1, what entropy detects, why brand distance catches typosquatters).
5. **The Model Arena (Benchmark Lab)**:
   - Interactive comparison table of all 6 algorithms.
   - Confusion matrix inspector with percentage normalization.
   - Latency vs Accuracy scatter/trade-off plot.
6. **Data Integrity Story**:
   - The truth about dataset overlap (84.6% leakage exposed) and how domain-grouped StratifiedGroupKFold solves it.

---

## 5. Micro-Interactions & Feel
- **Transitions**: Smooth bezier curves (`cubic-bezier(0.16, 1, 0.3, 1)`), 200–300ms duration.
- **Card Hover States**: Subtle 1px elevation lift, border color transition to primary accent, zero jarring shifts.
- **Data Visualizations**: Crisp SVG or Canvas rendering, high DPI, interactive tooltips on hover.
- **Responsive**: Mobile-first fluid grids, collapsible sidebars, touch-friendly tap targets (minimum 44×44px).
