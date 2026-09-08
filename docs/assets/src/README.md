# Asset sources

How the README's terminal screenshots are made. Recorded because the pipeline had to be
reverse-engineered once already.

## Report card (`report-compact.png`)

The README's first screenshot is the **HTML report**, not the terminal one — the surface whose
identity and layout the skill controls end to end. `report.png`, the longer excerpt inside the
collapsed `<details>`, is still a terminal capture (next section).

```bash
python3 -m clawseccheck --home fixtures/home_vuln --no-history --html card.html
```

Then rasterize at 2x and crop:

```bash
google-chrome --headless --disable-gpu --no-sandbox --hide-scrollbars \
  --force-device-scale-factor=2 --window-size=1000,1700 \
  --screenshot=card.raw.png "file://$PWD/card.html"
python3 -c "from PIL import Image; im=Image.open('card.raw.png').convert('RGB'); \
  im.crop((0,0,im.width,1000)).save('report-compact.png', optimize=True)"
```

**`1000` is not a chosen number, and must not be re-chosen by eye.** It is the `.header`
element's own bottom border (484 CSS px at a 1000 px viewport) plus 16 px of the container's
padding, doubled for the 2x capture — so the image ends on a real divider rather than mid-air.
Re-derive it after any change to the header, with the same renderer that takes the shot:

```bash
# append a probe to a COPY of card.html, then read it back out of the title
<script>addEventListener('load',()=>{const b=document.querySelector('.header').getBoundingClientRect();
 document.title='HDR='+Math.round(b.bottom+scrollY)+' WARN='+
 Math.round(document.querySelector('.warning-box').getBoundingClientRect().top+scrollY);});</script>
```

```bash
google-chrome --headless --disable-gpu --no-sandbox --virtual-time-budget=3000 \
  --window-size=1000,1400 --dump-dom "file://$PWD/probe.html" | grep -o '<title>[^<]*'
```

**The crop must never reach the `⚠ Private Report` box**, which the probe reports as `WARN`.
That banner says the report "must **NOT** be shared publicly" — inside an image whose whole
purpose is to be shared publicly. It is HTML-only (`report.py:5595`); neither the text report
nor either committed `.ansi` slice has it, so this contradiction is one the HTML capture would
introduce on its own. At the time of writing the crop clears it by 12 CSS px; that margin is
the reason the bound is anchored rather than eyeballed.

**Pin the colour scheme explicitly — do not rely on the default.** `report.py` styles the dark
variant through `@media (prefers-color-scheme: dark)` and offers no manual toggle, and headless
Chrome answers that query from the *machine's* desktop theme. On the maintainer's box the command
above produces the DARK card with no flag at all; on a light-themed machine the identical command
produces the light one. The shipped image is the dark card, which also keeps it in the same visual
language as `report.png` and the banner. To force the other one, neuter the query in a copy:

```bash
sed 's/@media (prefers-color-scheme: dark)/@media (max-width: 1px)/' card.html > card-light.html
```

Everything the image shows comes from that one command against the repo's own vulnerable fixture
— nothing is composed, and unlike the `.ansi` slices below, a screenshot cannot elide. That is
also why the crop stops where it does: the section under it contains a host-level finding that
prints the maintainer's real home path, because some checks inspect the running host regardless
of `--home`.

## Terminal screenshots (`report.png`, `report-compact.png`)

Each PNG is a real capture, never hand-drawn. Three steps:

1. **Capture** a colour run of the audit and cut a slice from it:

   ```bash
   FORCE_COLOR=1 python3 -m clawseccheck.cli --home fixtures/home_vuln --no-history > run.ansi
   ```

   The committed slices — `report_slice.ansi` and `report_compact_slice.ansi` — are excerpts
   of exactly that output, stitched from non-contiguous line ranges. Omitted material is
   marked with a `…` line. **Nothing in a slice is edited or retyped**: a value that would be
   wrong in a screenshot (a fixture path, say) is *elided*, not rewritten, so the image can
   only ever show output the tool really produced.

2. **Render** the slice to a styled terminal frame:

   ```bash
   python3 docs/assets/src/ansi2html.py report_slice.ansi report.html \
     "clawseccheck — auditing ~/.openclaw" 760
   ```

   `760` is the frame width both shipped PNGs use — keep it, or the two images stop matching
   each other in the README.

3. **Rasterize** `report.html` at 2× and crop to the alpha bounding box (any headless browser
   plus any image library will do; Pillow's `Image.getbbox()` does the crop). What was actually
   used, recorded so the next person does not reverse-engineer it a third time:

   ```bash
   google-chrome --headless --disable-gpu --no-sandbox --hide-scrollbars \
     --force-device-scale-factor=2 --default-background-color=00000000 \
     --window-size=816,2600 --screenshot=report.raw.png "file://$PWD/report.html"
   python3 -c "from PIL import Image; im=Image.open('report.raw.png').convert('RGBA'); \
     im.crop(im.getbbox()).save('report.png')"
   ```

   `816` is not arbitrary: it is the `760` frame plus the stylesheet's `28px` body padding on
   each side. The frame's drop shadow spreads wider than that, so a *wider* window lets
   `getbbox()` find the shadow's own edge and the PNG comes out 877 CSS px instead of 816 —
   the two shipped images would stop matching each other and every earlier capture. Set the
   window to the padding box and the shadow is clipped to it, which is what the committed
   images (1632 px = 816 × 2) already are.

   **The rasterizer is not a project dependency, and must not become one.** ClawSecCheck has
   zero runtime *and* zero dev-tooling dependencies; this last step uses whatever happens to
   be on the maintainer's machine, and the PNG is committed as a binary artifact. Adding a
   headless browser to the repo's tooling is a separate, explicit decision — see
   `scripts/gen_banner.py`, which draws the same line for the banner.

## Banner (`banner.html` → `banner.png`, `banner-readme.png`)

`banner.html` is **generated** — do not hand-edit it:

```bash
python3 scripts/gen_banner.py --write
```

It derives the accent colours from `clawseccheck/brand.py`, the single source of brand truth,
so the banner cannot drift from the palette the tool itself renders. Rasterizing it to PNG is
the same manual step as above.
