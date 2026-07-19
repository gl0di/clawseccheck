#!/usr/bin/env python3
"""Generate docs/assets/src/banner.html from clawseccheck.brand — the single source
of brand truth — so the README banner's logo mark and accent colour can never drift
from brand.py the way they previously could (the file matched brand.py's values only
by hand-kept coincidence, not by construction).

Scope, fixed on purpose (do not silently grow this):
  * This script owns ONLY the deterministic generation of the banner's HTML/CSS
    *source* (docs/assets/src/banner.html) from brand.py constants.
  * It does NOT rasterize banner.html into the shipped PNGs
    (docs/assets/banner.png, docs/assets/banner-readme.png). Producing those stays
    a manual step, exactly as it was before this script existed — this repo has
    zero runtime OR dev-tooling dependency on a headless browser
    (playwright/puppeteer-equivalent), and adding one is an explicit, separate
    decision for Dave (CLAUDE.md Golden Rule #1: stdlib only, everywhere). Do not
    treat the PNGs as "generated automatically" by this script — they are not.

Usage:
    python3 scripts/gen_banner.py             # print the generated HTML to stdout
    python3 scripts/gen_banner.py --write     # write docs/assets/src/banner.html

Deterministic: the same brand.py constants always produce byte-identical output, so
running this twice in a row never changes the file a second time (idempotent). No
network, no clock, no randomness.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from clawseccheck import brand  # noqa: E402  (sys.path bootstrap above must run first)

OUTPUT = ROOT / "docs" / "assets" / "src" / "banner.html"

# ── The logo slot's geometry ─────────────────────────────────────────────────
#
# The mark itself renders at MARK_PX; the *slot* that holds it is wider, at
# SLOT_W_PX, and the mark is centred inside it.
#
# Why the slot is wider than the mark, and why this exact number: the banner used
# to put the MASCOT emoji here at ``font-size: 84px``. A glyph's box is its
# advance width, not its font-size — Noto Color Emoji's 🦞 advances 104.81px at
# 84px — so the emoji occupied a 104.81 x 84 box, ~10.4px of side bearing on each
# side of ~84px of ink. Dropping in an 84 x 84 SVG therefore does NOT preserve the
# composition: it narrows the slot by 20.81px, and because `.brand` is a flex row
# feeding `.left {flex: 1.25}`, that shortfall propagates — measured in headless
# Chrome at 1280x640, `h1` x 210.81 -> 190.00, `.left` w 660.83 -> 640.02 and the
# whole terminal `.card` x 800.83 -> 780.02. The wordmark and the entire right-hand
# card slide left, and `.promise` stops being clamped by its own max-width.
#
# Pinning the slot to the width the emoji actually held keeps every other element
# where the shipped PNG has it (so re-rasterizing is a mark swap, not a
# recomposition) and restores the optical breathing room the side bearings gave
# between mark and wordmark. It also makes the geometry *more* stable than before:
# the composition no longer depends on which emoji font the rasterizing machine
# happens to have installed.
#
# This is a deliberate design constant, not a stray magic number. brand.LOGO_SVG is
# PROVISIONAL (see brand.py) — when the final mark art lands, revisit the slot
# rather than assuming this number still serves it.
MARK_PX = 84
SLOT_W_PX = 104.81


def _hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    """``"#e34234"`` -> ``(227, 66, 52)`` — the banner's glow/shadow rgba(...) stops
    are decimal triples, not hex, so this is the one conversion point."""
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def build_banner_html() -> str:
    """Return the banner's HTML/CSS source, built entirely from brand.py constants.
    Pure — no I/O, no filesystem access — safe to call from a test."""
    r, g, b = _hex_to_rgb(brand.BRAND_RED)
    rgb = f"{r},{g},{b}"
    red = brand.BRAND_RED
    # E-048's third LOGO_SVG leg: the banner is an HTML/badge-only surface (brand.py's
    # Tier 3), so it carries the graphical mark itself rather than the MASCOT emoji
    # glyph — single-sourced from brand.LOGO_SVG, never pasted/hand-drawn here or in the
    # generated HTML. Two details are copied deliberately from report.py's --html export,
    # which embeds the same constant:
    #   * the SVG is inlined verbatim and sized purely via CSS on the wrapper;
    #   * the wrapper is aria-hidden. LOGO_SVG carries its own
    #     role="img" aria-label="ClawSecCheck", and it sits immediately before the
    #     <h1>ClawSecCheck</h1> wordmark — without aria-hidden a screen reader would
    #     announce the brand name twice. The adjacent text is the real accessible name.
    logo_svg = brand.LOGO_SVG
    return f"""<!doctype html><meta charset="utf-8">
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; width: 1280px; height: 640px; overflow: hidden;
         font-family: system-ui, "Segoe UI", Roboto, "DejaVu Sans", sans-serif;
         background:
           radial-gradient(900px 500px at 78% 18%, rgba({rgb},.16), transparent 60%),
           radial-gradient(700px 420px at 12% 88%, rgba({rgb},.10), transparent 60%),
           linear-gradient(135deg, #191012 0%, #120b0d 55%, #0d090b 100%);
         color: #f2ece8; display: flex; align-items: center; }}
  .wrap {{ display: flex; width: 100%; padding: 0 84px; align-items: center; gap: 56px; }}
  .left {{ flex: 1.25; }}
  .brand {{ display: flex; align-items: center; gap: 22px; }}
  .claw {{ width: {SLOT_W_PX}px; height: {MARK_PX}px; display: flex; line-height: 0;
          align-items: center; justify-content: center; }}
  .claw svg {{ width: {MARK_PX}px; height: {MARK_PX}px; display: block;
              filter: drop-shadow(0 6px 22px rgba({rgb},.45)); }}
  h1 {{ margin: 0; font-size: 78px; font-weight: 800; letter-spacing: -1.5px; }}
  h1 .sec {{ color: {red}; }}
  .tag {{ margin: 14px 0 0 4px; font-size: 25px; color: #c9b8b2; font-style: italic; }}
  .promise {{ margin: 26px 0 0 4px; font-size: 30px; line-height: 1.35; color: #f2ece8;
             font-weight: 600; max-width: 640px; }}
  .pills {{ display: flex; gap: 14px; margin: 34px 0 0 4px; }}
  .pill {{ border: 1.5px solid #4a3733; background: rgba(255,255,255,.035); border-radius: 999px;
          padding: 11px 22px; font-size: 21px; font-weight: 600; color: #e8ddd8; }}
  .pill b {{ color: #ff7b6b; }}
  .url {{ position: absolute; left: 88px; bottom: 40px; font-size: 20px; color: #8d7d77;
         font-family: "DejaVu Sans Mono", monospace; }}
  .card {{ flex: .9; background: #14100f; border: 1px solid #332723; border-radius: 18px;
          box-shadow: 0 24px 64px rgba(0,0,0,.55); padding: 30px 34px 34px; }}
  .cbar {{ display: flex; gap: 8px; margin-bottom: 22px; }}
  .cdot {{ width: 12px; height: 12px; border-radius: 50%; }}
  .clabel {{ font-size: 19px; color: #9a8b85; margin-bottom: 16px;
            font-family: "DejaVu Sans Mono", monospace; }}
  .grades {{ display: flex; gap: 12px; }}
  .g {{ width: 62px; height: 72px; border-radius: 12px; display: flex; align-items: center;
       justify-content: center; font-size: 38px; font-weight: 800;
       background: rgba(255,255,255,.05); color: #6d5f59; border: 1px solid #332723; }}
  .g.on {{ background: linear-gradient(160deg, #4ec96e, #2e9c50); color: #08140b;
          border-color: transparent; box-shadow: 0 8px 26px rgba(78,201,110,.35); }}
  .g.f {{ color: #a0524a; }}
  .meter {{ margin-top: 22px; height: 10px; border-radius: 6px; overflow: hidden;
           background: #241a17; }}
  .meter div {{ height: 100%; width: 78%;
               background: linear-gradient(90deg, {red}, #e8a33d, #4ec96e); }}
  .cfoot {{ margin-top: 20px; font-size: 18.5px; line-height: 1.5; color: #b4a59f;
           font-family: "DejaVu Sans Mono", monospace; }}
  .cfoot .ok {{ color: #7ee787; }}
</style>
<body>
<div class="wrap">
  <div class="left">
    <div class="brand"><div class="claw" aria-hidden="true">{logo_svg}</div>
      <h1>Claw<span class="sec">Sec</span>Check</h1>
    </div>
    <div class="tag">The claw that checks your claws.</div>
    <div class="promise">Local, read-only security audit for your OpenClaw agent.</div>
    <div class="pills">
      <div class="pill"><b>●</b>&nbsp; Offline</div>
      <div class="pill"><b>●</b>&nbsp; Read-only</div>
      <div class="pill"><b>●</b>&nbsp; Zero dependencies</div>
    </div>
  </div>
  <div class="card">
    <div class="cbar">
      <div class="cdot" style="background:#ff5f56"></div>
      <div class="cdot" style="background:#febc2e"></div>
      <div class="cdot" style="background:#28c840"></div>
    </div>
    <div class="clabel">$ clawseccheck</div>
    <div class="grades">
      <div class="g on">A</div><div class="g">B</div><div class="g">C</div>
      <div class="g">D</div><div class="g f">F</div>
    </div>
    <div class="meter"><div></div></div>
    <div class="cfoot">scores your setup <span class="ok">A–F</span><br>
      finds the urgent holes<br>no API key · no network</div>
  </div>
</div>
<div class="url">github.com/gl0di/clawseccheck</div>
</body>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate docs/assets/src/banner.html from brand.py.")
    parser.add_argument("--write", action="store_true", help="write banner.html instead of printing")
    args = parser.parse_args(argv)

    body = build_banner_html()
    if args.write:
        OUTPUT.write_text(body, encoding="utf-8")
        return 0
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
