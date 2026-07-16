"""Convert captured ANSI terminal output to a styled HTML terminal frame."""
import html
import re
import sys

PALETTE = {
    30: "#3b3b3b", 31: "#ff5f56", 32: "#4ec96e", 33: "#e8a33d",
    34: "#6ca9f0", 35: "#c792ea", 36: "#56c8d8", 37: "#d8d8d8",
    90: "#7a7a7a", 91: "#ff7b72", 92: "#7ee787", 93: "#f0c674",
    94: "#79b8ff", 95: "#d2a8ff", 96: "#7fdbca", 97: "#ffffff",
}

CUBE = [0, 95, 135, 175, 215, 255]


def color256(n):
    if n < 16:
        base = [30, 31, 32, 33, 34, 35, 36, 37, 90, 91, 92, 93, 94, 95, 96, 97]
        return PALETTE[base[n]]
    if n < 232:
        n -= 16
        r, g, b = CUBE[n // 36], CUBE[(n // 6) % 6], CUBE[n % 6]
        return f"#{r:02x}{g:02x}{b:02x}"
    v = 8 + (n - 232) * 10
    return f"#{v:02x}{v:02x}{v:02x}"


def convert(text):
    out, open_span = [], False
    parts = re.split(r"(\x1b\[[0-9;]*m)", text)
    for part in parts:
        m = re.match(r"\x1b\[([0-9;]*)m", part)
        if not m:
            out.append(html.escape(part))
            continue
        params = [int(p) for p in (m.group(1) or "0").split(";") if p != ""] or [0]
        styles = []
        i = 0
        while i < len(params):
            p = params[i]
            if p == 0:
                styles = None  # reset
            elif p == 1:
                (styles or []).append("font-weight:bold")
            elif p == 2:
                (styles or []).append("opacity:.7")
            elif p == 4:
                (styles or []).append("text-decoration:underline")
            elif p in PALETTE:
                (styles or []).append(f"color:{PALETTE[p]}")
            elif p == 38 and i + 2 < len(params) and params[i + 1] == 5:
                (styles or []).append(f"color:{color256(params[i + 2])}")
                i += 2
            elif p == 48 and i + 2 < len(params) and params[i + 1] == 5:
                (styles or []).append(f"background:{color256(params[i + 2])}")
                i += 2
            i += 1
        if open_span:
            out.append("</span>")
            open_span = False
        if styles:
            out.append(f'<span style="{";".join(styles)}">')
            open_span = True
    if open_span:
        out.append("</span>")
    return "".join(out)


TEMPLATE = """<!doctype html><meta charset="utf-8">
<style>
  body {{ margin: 0; padding: 28px; background: transparent; }}
  .term {{
    width: {width}px; margin: 0 auto; border-radius: 12px; overflow: hidden;
    background: #14100f; border: 1px solid #2c2320;
    box-shadow: 0 18px 48px rgba(0,0,0,.5);
    font-family: "JetBrains Mono", "Fira Code", "DejaVu Sans Mono", Menlo, monospace;
  }}
  .bar {{ display: flex; align-items: center; gap: 8px; padding: 11px 14px;
         background: #1e1715; border-bottom: 1px solid #2c2320; }}
  .dot {{ width: 12px; height: 12px; border-radius: 50%; }}
  .title {{ margin-left: 10px; color: #9a8f8a; font-size: 12.5px; }}
  pre {{ margin: 0; padding: 18px 20px 20px; color: #d8d2cd; font-size: 13px;
        line-height: 1.42; white-space: pre-wrap; word-break: break-word; }}
</style>
<body>
<div class="term">
  <div class="bar">
    <div class="dot" style="background:#ff5f56"></div>
    <div class="dot" style="background:#febc2e"></div>
    <div class="dot" style="background:#28c840"></div>
    <div class="title">{title}</div>
  </div>
  <pre>{body}</pre>
</div>
</body>
"""

if __name__ == "__main__":
    src, dst, title, width = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    text = open(src, encoding="utf-8", errors="replace").read()
    open(dst, "w", encoding="utf-8").write(
        TEMPLATE.format(body=convert(text), title=html.escape(title), width=width)
    )
    print("wrote", dst)
