# Asset sources

How the README's terminal screenshots are made. Recorded because the pipeline had to be
reverse-engineered once already.

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
