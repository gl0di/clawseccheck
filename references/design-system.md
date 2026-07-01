# ClawSecCheck — Design System

Single source of truth for **how ClawSecCheck looks and sounds**: layout, copy/voice,
mascot, glyph legend, and — crucially — how each screen renders across the different
channels OpenClaw delivers on. English-only (the former `i18n.py` he/en layer was removed).

> Why a separate doc: keeping the look here de-bloats `SKILL.md` (which stays the
> *operating* manual: flags, mode-map, integrity rules) and gives every render surface one
> shared contract.

## Core principle: ClawSecCheck is a skill → output is channel-relayed text

ClawSecCheck produces **text the host OpenClaw agent relays to the user over whatever
channel they're on** — Telegram, Discord, Slack, web ControlUI, or a terminal. Those
channels have **different rendering capabilities**, so there is **no single fixed visual
skeleton**. Alignment-dependent box-drawing (closed boxes, columns) + "type 1-4" is a
*terminal* assumption that breaks on Telegram.

Both the `SKILL.md` Dashboard (Step 3) and the CLI text report (`render_report`) apply this
everywhere **except** the family section headers, which use an **open 3-sided frame**
(`┌─ / │ label / └─`, no right border) so the seven categories visibly stand apart. That
single exception is deliberate (see Layer 2 and Component 3): with no right border there is
nothing to align, so the frame renders as three short lines in a monospace surface (terminal,
ControlUI) **and** degrades to harmless plain lines in a proportional one — and Telegram
flattens the Dashboard through `delivery-mirror` regardless. The CLI text report uses the
same frame in its default (non-ascii) profile and falls back to `[Family] — N to fix` brackets
under `--ascii`. Everything else stays emoji + indentation + markdown, **not** box-art.

### Surface capability matrix

| Surface | Box-art / monospace | Color | Text formatting | Native buttons (from a skill) |
|---|---|---|---|---|
| **Terminal / TUI** (`openclaw` cli) | ✅ | ✅ ANSI | ⚠️ weak | ❌ → "say 1 / go" |
| **ControlUI** (web chat) | ⚠️ code-block only | ❌ no ANSI | ❓ markdown undocumented | ❓ undocumented (not in capability table) |
| **Telegram** | ⚠️ code-block only, ugly on mobile | ❌ | **HTML** default · markdown via `richMessages` | ✅ inline buttons — gated by `capabilities.inlineButtons` |
| **Discord · Slack · Teams · Mattermost · Feishu** | — | — | native | ✅ native (components / Block Kit / cards) |

Grounded via OpenClaw docs (`plugins/message-presentation`, `channels/telegram`,
`cli/message`): a skill **can** emit channel-native buttons through the portable
`MessagePresentation` layer — Core maps semantic blocks to each channel's widgets. **Two
caveats that keep `text` the contract:** (1) Telegram buttons are **capability-gated**
(`channels.telegram.capabilities.inlineButtons`, default `allowlist`) so they may be off;
(2) **ControlUI buttons + markdown are undocumented** → treat web chat as plain text/bubbles.

---

## Three layers

### Layer 0 — Tokens

- **Voice:** plain language always — never internal codes (`B2 FAIL`); describe the real
  risk in one sentence. Calm, not alarmist. Lead with the law: *local · read-only · nothing
  leaves your machine.* Second person, owner's frame ("your agent", *"OpenClaw Security
  Audit"*).
- **Mascot:** 🦞 (the *Claw*) — header line only, once. ASCII mode drops it.
- **Brand line:** `🦞 ClawSecCheck {version} · built {N} days ago`
- **Severity = emoji, not color** (color doesn't survive most channels):

  | Glyph | Meaning |
  |---|---|
  | ⛔ | blocking / critical |
  | ⚠️ | warning / caution |
  | ✓ | pass / clean |
  | ℹ | informational notice |
  | 🦞 | brand mascot (header only) |

### Layer 1 — Components (semantic slots, no visual commitment)

Every screen is a set of slots. The slots are channel-agnostic; **Layer 2** decides how they
render.

```
Title      — what this screen is (context line)
Intro      — optional transparency / framing text
Choices[]  — selectable options (menu)
Findings[] — ranked risk items (plain-language)
Status     — footer: config path · last-run age · version
Actions[]  — what you can do next
```

**These slots map onto OpenClaw's real `MessagePresentation` blocks** (so we ride the
framework's abstraction instead of inventing one): `Title`→card title/tone · `Intro`/`Status`
→`text`/`context` · section breaks→`divider` · `Choices[]`/`Actions[]`→`buttons` (or `select`
for long lists) · `Findings[]`→repeated `text` blocks. The agent's reply IS the presentation
payload — we never use `message send --to <other target>` (that would be an outbound action,
breaking read-only). Authoring screens to these block names keeps `text`↔`interactive` a
pure rendering switch.

#### Screen inventory (the full page map)

| # | Screen | Surface(s) | Trigger | Status |
|---|---|---|---|---|
| **Entry** ||||
| 1 | **Welcome** (pre-scan menu) | guided | Step 1 / audit request | ✅ drawn |
| 2 | **Next-actions** (post-result menu) | guided | Step 4 | ▢ todo |
| **Results** ||||
| 3 | **Dashboard** (A–F audit) | guided + CLI | Step 3 / `audit.py` | ✅ drawn |
| 4 | **What-changed** (diff vs last) | guided + CLI | `--monitor` | ▢ todo |
| 5 | **Vet verdict** (skill / MCP supply-chain) | guided + CLI | `--vet` / `--vet-mcp` | ▢ todo |
| 6 | **Self-test** (canary · red-team · dry-run) | guided + CLI | `--self-test` | ▢ todo |
| **Reusable blocks** ||||
| 7 | **Finding card** (one risk) | both | inside 3/4 | ▢ stub |
| 8 | **Fix prompts** (copy-paste) | both | `--fix` | ▢ todo |
| 9 | **Notices** (freshness / update / private) | both | inline | ▢ stub |
| **Artifacts** ||||
| 10 | **Badge / card** (shareable) | CLI | `--card` | ▢ todo |
| 11 | **HTML report** | CLI | `--html` | ✅ drawn |
| **Discovery & onboarding** ||||
| 12 | **Menu / All functions** (capability palette) | guided | "menu" / `?` / `[More…]` | ✅ drawn |
| 13 | **No-config / first-run** (`~/.openclaw` missing) | guided + CLI | empty/missing home | ✅ drawn |
| 14 | **Update flow** (check → result → offer) | guided | "update" / `[Check update]` | ▢ todo |

> Also pending: a **clean-result Dashboard** variant (Grade A / 0 issues) — Component 3 must
> cover the "all good" state, not just the vulnerable case.

### Layer 2 — Render profiles

One component → up to three renderings. **`text` is the contract every screen MUST satisfy;**
`mono` and `interactive` are progressive enhancements, never required to operate.

- **`text` — baseline, ALL channels.** Markdown headers + emoji severity + numbered choices
  ("say 1 / go") + indentation. **No color, no buttons, and no alignment-dependent box-art**
  (closed boxes, aligned columns) — those need monospace and break on Telegram. The **one
  sanctioned frame** is the family-header **open 3-sided box** (`┌─ / │ label / └─`, no right
  border): with nothing to align on the right it survives proportional fonts as three short
  lines instead of a broken grid. If a screen works here, it works everywhere.
- **`mono` — terminal / TUI enhancement.** May add closed box-drawing, aligned columns, ANSI color.
  `--ascii` strips emoji + box back toward `text`. The CLI report (`report.py`) implements the
  colour tier: grade letter, score-bar fill and severity icons are ANSI-painted **only** for an
  interactive TTY, and switched off by `--no-color` / `NO_COLOR` (piped output is plain). Colour
  is purely additive — `ansi.strip_ansi()` restores the exact `text` bytes, so `--save` files
  and non-terminal consumers never carry escape codes.
- **`interactive` — button-capable channels (Telegram, Discord, Slack, Teams, Mattermost,
  Feishu).** `Choices[]`/`Actions[]` → native buttons via `MessagePresentation`. Grounded.
  **Must degrade gracefully:** buttons are capability-gated (Telegram default `allowlist`,
  may be off) and undocumented on ControlUI — so a screen always ships its `text` form too,
  and the agent uses buttons only when the channel supports them. Button clicks return as
  `callback_data` text the agent already knows how to route.

---

## Components

### 1. Welcome — entry menu · guided Step 1   _(v3 — shipped as `--menu`)_

The single front door. **Minimalist:** four items, not a wall of flags. Shipped as a real
command — `clawseccheck --menu` renders this exact screen (`clawseccheck/menu.py`,
`render_menu()`), so the guided agent and the CLI share one grounded source instead of
hand-kept prose. Version from `__version__`; "last check" age from local score history;
the staleness line from the offline `update_notice()` (no network).

**Slots:** Title=brand line · Choices=4 items · Status=two nudges (last-check + staleness).

**`text` profile (baseline — Telegram / web / terminal — anywhere):**

```
🦞 ClawSecCheck · v{version}

  1  🔍 Check everything        config + live agent test ⚡
  2  📦 Check before install    skill · plugin · MCP
  3  📄 Report & history        show · save · trend · badge
  4  📋 Menu                    everything else: verify · version · HTML · SARIF…

  🕒 Last check: {N} days ago        (omitted when there's no history yet)
  🆙 Build is {N} days old — a newer one may exist · say "update"   (only when stale)
```

**`mono` / `--ascii` profile:** emoji fold to ASCII (🦞 dropped, ⚡→`(live)`, `·`→`-`,
`…`→`...`); `_ascii()` in `menu.py` owns the mapping. Verified by `tests/test_menu.py`.

**`interactive` profile (Telegram & friends):** the four items → a `buttons` block; the
numbered/`text` list is the fallback when `capabilities.inlineButtons` is off. A tapped
button returns its label as the spoken choice (`callback_data`).

**Decisions baked in:**
- **One comprehensive check is the hero.** Item 1 = `--full` (read-only audit **+** live
  self-test **+** MCP vet). The ⚡ in the label **discloses** the live-agent test up front,
  so selecting item 1 **is** the consent — no separate "are you sure?" prompt (the user's
  call: *picking it = consenting*). Read-only-by-default stays honest because the active
  part is named before the choice; guided flow still runs the read-only audit first, shows
  the Dashboard, then the live test.
- **🦞 mascot** in the header, once; consistent with the Dashboard.
- **No fabricated runtime.** No "~1s" claim — we don't assert an unmeasured speed (law #4).
- **Two grounded nudges:** 🕒 last-check age from local history ("not checked yet" when
  empty); 🆙 the update affordance is **always shown** so "update" is discoverable — quiet
  by default (`say "update" to check for a newer version`) and **louder when the offline
  `update_notice()` fires** (names the build age). Never a network call; on "update" the
  **host agent** checks ClawHub and offers `openclaw skills update clawseccheck`.
- **Discoverability via item 4.** Everything else (verify, monitor/"what changed", deeper
  `--ask`/`--attest`, html, sarif, percentile, risk-paths, prompts, the `private` modifier)
  lives behind **"Menu"** — reachable, but off the minimal front door.

### 2. Next-actions — post-result menu · guided Step 4   _(v2 — F-043/C-132)_

Appended to the end of every Dashboard message (Section 7), not a separate turn. Five
lettered items, always the same five slots — no "deeper scan" pick (folded into the scan
itself, see Component 3) and no confirmation redundancy (picking a lettered item **is** the
consent, same principle as Welcome item 1).

**`text` profile:**

```
Next — ✅ read-only · ⚡ touches live agent (asks)
  a ✅ Copy-paste fixes     b ⚡ Live injection test
  c ✅ Turn on monitoring   d ✅ Save full report   e ✅ Menu   Start with a?
```

**Decisions baked in:**
- **No "deeper" item.** Pre-F-043 this was a 5th lettered pick ("resolve UNKNOWN"). The
  capability self-report (`--ask`→`--attest`) now runs automatically the first time the
  user picks Welcome item 1 (see `SKILL.md` Step 2) — offering it again here would be
  asking the user to re-confirm something that already happened.
- **d/e are standing, not conditional.** a/b/c adapt to the audit result (SKILL.md Step 4
  routing table); "save full report" and "back to menu" are always useful regardless of
  grade, so they're unconditional — this is what "в конце дать файл/отчёт/меню" (the design
  session's closing-menu ask) resolved to.
- **d maps to `--save`**, not `--html`/`--sarif` — those stay Menu-only (item 4 → Screen 12)
  since they're export formats, not the default "give me the report" ask.

### 3. Dashboard — audit result · guided Step 3   _(v2 — F-044)_

The full scan result. Seven sections in one message (SKILL.md Step 3); Section 3 (Findings)
is the part this version reworked — grouped by OpenClaw surface family instead of a flat
severity list, with the Lethal Trifecta folded in as one Privilege & Execution finding
instead of a standalone headline. Source: `audit.py --json` (guided) / `audit.py --full`
(CLI text — `clawseccheck/report.py:render_report`, same grouping, F-044).

**Slots:** GradeCard · FixFirst · Findings[grouped by 7 families] · Coverage · WorthAGlance
· ScopeNote · NextActions (Component 2).

**`text` profile (abridged — full section-by-section spec lives in `SKILL.md` Step 3):**

```
🦞 OpenClaw Security Audit — Grade F · 49/100
████████░░░░░░░░  ·  21 issues

▶ FIX FIRST
{plain-language top1 finding}
Projected: fix this → C (74) · fix all Critical+High → B (81)

— Findings —
┌──────────────────────────────
│ 🌐 Exposure & Network
└──────────────────────────────
🔴 CRITICAL  insecure control-UI auth
    why: anyone on your local network can send commands to your agent right now
    fix: set gateway.controlUi.allowInsecureAuth to false in openclaw.json

┌──────────────────────────────
│ 🔑 Privilege & Execution
└──────────────────────────────
🔴 CRITICAL  Lethal Trifecta — all three legs active
    why: your agent receives outside input, has access to sensitive data, and can act
    online — one injected prompt is enough to exfiltrate everything
    fix: break the trifecta — remove one leg
🟠 HIGH  tool profile broader than minimal
    why: the "coding" profile gives filesystem write, shell, and package-install access
    fix: change tools.profile to "minimal"

— Coverage of OpenClaw surfaces —
✅ Checked 11 · ◑ Partial/UNKNOWN 2  (of 13 surfaces)

Next — ✅ read-only · ⚡ touches live agent (asks)
  a ✅ Copy-paste fixes     b ⚡ Live injection test
  c ✅ Turn on monitoring   d ✅ Save full report   e ✅ Menu   Start with a?
```

**Decisions baked in:**
- **Grouped by family, not severity-flat (F-044).** Reading "here's what's wrong with your
  network exposure" beats a mixed CRITICAL→LOW dump — findings only make sense next to their
  peers in the same surface. Order is fixed (`catalog.FAMILY_ORDER`); a family with nothing
  to fix is simply omitted from the chat Dashboard (the CLI text report still prints an empty
  "— clear" header per family — useful there for coverage-proof, noisy here).
- **Family headers are framed (open 3-sided box).** Each family title renders inside
  `┌─ / │ 🌐 Exposure & Network / └─` so the seven categories read as distinct sections
  instead of blending into the finding list. The box is **open on the right on purpose**: a
  closed box (`│ … │`) needs the right border to line up, and emoji render at variable width
  so it visibly breaks; with no right border there is nothing to misalign, so the frame holds
  in monospace surfaces and degrades to three harmless lines elsewhere. This is the single
  box-art exception to the `text` baseline (Layer 2). The findings sit **below** the frame,
  not inside it. The CLI text report (`render_report`) **now also frames family headers** in
  its non-ascii / `mono` profile (open 3-sided, no emoji, preserving the `— N to fix` /
  `— clear` count) — consistent with the chat Dashboard. Under `--ascii`, `render_report`
  degrades to the `[Family] — N to fix` bracket form.
- **Chat Section 3 is a *paste*, not model-composed (F-070).** Live testing showed the host LLM
  ignores the frame instruction and substitutes markdown-bold headers when it composes Section 3
  itself. So SKILL.md Step 3 now runs `audit.py --dashboard-findings`
  (→ `report.py:render_dashboard_findings`) and pastes the output verbatim: the renderer emits only
  non-suppressed FAIL/WARN, high-confidence findings, already framed — so the frame is
  deterministic and the FAIL/WARN + no-`MEDIUM`/`ATTESTED` filter is enforced by code, not the model.
- **No Lethal Trifecta headline chip.** It moved from Section 1 (grade card) into Section 3
  as the A1 finding inside Privilege & Execution — a agent-behavior signal among its peers,
  not a separate "the one thing that matters" banner. The 3-legs plain-language explanation
  that used to live in the headline now becomes A1's `why:` line.
- **"Show all findings"**, not just FAIL/WARN: the CLI text report (`render_report`) lists
  PASS as one-line confirmations per family and tallies UNKNOWN as a single count
  ("N not assessed — resolve via `--ask` then `--attest`") rather than enumerating each one
  — proves coverage without a wall of near-identical "not assessed" lines. The chat Dashboard's
  Section 3 (now a paste of `--dashboard-findings`, see above) is FAIL/WARN-only **and**
  high-confidence-only — the renderer drops PASS/UNKNOWN (they own Sections 4/6) and
  `MEDIUM`/`ATTESTED` (they own Section 5), so nothing is double-listed across the message.
- **"deeper" is not a Section-3/7 pick anymore (F-043).** The capability self-report
  (B43/B44) runs automatically in Step 2 the first time item 1 is chosen, so by the time this
  screen renders those UNKNOWNs are usually already resolved — Section 4's coverage note only
  suggests `--ask`/`--attest` for surfaces attestation can't already have covered.

### 4. What-changed — `--monitor`
_Stub. Diff vs last snapshot._

### 5. Vet verdict — `--vet` / `--vet-mcp`
_Stub. Supply-chain verdict for a skill / MCP server._

### 6. Self-test — `--self-test`
_Stub. canary · red-team · dry-run results._

### 7. Finding card
_Stub. One risk: plain-language title · why · copy-paste fix. No internal codes._

### 8. Fix prompts — `--fix`
_Stub. Copy-paste remediation prompts._

### 9. Notices — freshness / update / private
_Stub. The ℹ lines: config-age nudge, update result, "private" (no-history) confirmation._

### 10. Badge / card — `--card`
_Stub. Shareable badge._

### 11. HTML report — `--html`   _(v2 — 2.8.0)_

The private owner-view export (`clawseccheck/report.py:render_html`). A **single
self-contained `.html` file** — inline `<style>`, **no external assets** (no CDN, no
`<link>`, no web fonts), enforced by `tests/test_html.py`. This is the one surface that is
*not* channel-relayed text: it's a file the owner opens locally, so it uses the full visual
budget a browser gives (real color, layout, responsive) that the `text` profile can't.

**Slots (same semantics as Component 3, richer render):** GradeCard (grade badge + score
**progress bar** + Lethal Trifecta ratio + capped note) · Private-warning notice · Severity
summary strip (Critical/High/Medium/Low counts) · Findings **grouped by the 7 families**
(Component 3's grouping) with a per-group jump-nav and counts · Footer (local · read-only).

**Decisions baked in:**
- **Grouped by family, matching the Dashboard.** A `--html` on a real fleet is dozens of
  findings; the same 7-family grouping + in-page anchor nav keeps it navigable instead of an
  endless scroll.
- **Color is fair game here (unlike the `text` profile).** Severity drives card accents and
  the summary chips; the grade drives the badge + score bar. This surface is a browser, so
  the "severity = emoji not color" token (Layer 0) is relaxed to "emoji **and** color".
- **Light + dark via `prefers-color-scheme`** (CSS custom properties), still one file.
- **Private, not shareable.** Renders the full finding detail with an explicit "must NOT be
  shared publicly — use `--badge`" notice; the warning is a normal flowing line (the old
  `.warning-box strong { display:block }` bug that split "must **NOT** be shared" is fixed).

### 12. Menu / All functions — capability palette · "menu" / `?` / `[More…]` · `--functions`

The discoverability backstop for Welcome. Welcome shows only 4 common modes; **this is the
complete list** of what the skill can do, grouped by intent, so the user never has to know a
flag in advance. ✅ = read-only; ⚡ = exercises the live agent (the tool only *emits* the test
material — running it is the live part, and it's always confirm-gated). Every verb ties to its
grounding flag (in parens) so this palette and `cli.py` can't silently drift — it covers the
21 `_PRIMARY_MODES` plus the audit defaults and modifiers.

**`text` profile (baseline):**

```
🦞 ClawSecCheck — everything it can do

Scan  ✅ read-only
  Quick scan        "go" / "1"        {N} checks across your OpenClaw setup        (default)
  Capability re-check "deeper"       standalone self-report re-run (Check everything already does this once, automatically — F-043) (--ask→--attest)
  Full check        "full" / "3"      Quick + self-test + a vet of your MCP servers (--full)
  What changed      "what changed"    diff vs your last scan                        (--monitor)
  Fix it            "fix"             paste-ready fixes for findings (doesn't apply) (--fix / --prompts)
  Next steps        "next"            recommended actions from the result           (--next)
  Attack paths      "risk paths"      the highest-risk capability chains            (--risk-paths)
  Show suppressed   "suppressed"      findings you've muted, by id                  (--show-suppressed)

Live tests  ⚡ exercises your running agent — I confirm first
  Canary            "canary"          plant a marker, see if an injection leaks it  (--canary)
  Red-team          "red-team"        a payload suite to run against the agent      (--redteam)
  Dry-run           "dry-run"         trace what an injection would reach           (--dryrun)
  Self-test         "self-test"       all three at once                             (--self-test)

Vet before you trust  ✅ read-only
  Vet a skill       "vet <path>"      malware/supply-chain check before you install (--vet)
  Vet an MCP server "vet-mcp <name>"  same for a configured MCP server              (--vet-mcp)
  Vet everything    "vet all"         every installed skill, one verdict each       (--vet-all)

Track over time  ✅ read-only
  Trend             "trend"           how your score moved across past scans        (--trend)
  Percentile        "percentile"      where you stand vs typical setups (offline)   (--percentile)
  Watch log         "watch log"       timeline of what changed (Agent Watch journal)(--watch-log)

Share & export  ✅ read-only
  Badge             "badge"           shareable grade badge — SVG or text           (--badge / --card)
  HTML report       "html"            standalone HTML report                        (--html)
  SARIF             "sarif"           findings as SARIF 2.1.0 (CI / code scanning)  (--sarif)
  Save              "save <path>"     also write the report to a file               (--save)

Integrity  ✅ read-only
  Verify self       "verify"          SHA-256 of the engine source — tamper check   (--verify-self)

Add to any:
  "private"   don't record this run to history          (--no-history)
  "ascii"     plain ASCII, no emoji/box                  (--ascii)
  "update"    ask your agent to check ClawHub for a newer version   (agent-driven, Screen 14)

Power / CI flags (--json, --fail-under, --exit-code, --home, --seed, --no-host…): say "help".
```

**`mono` profile (terminal / TUI):** same list under box section-headers, columns aligned
(verb · words · flag). ASCII mode drops emoji/box.

**`interactive` profile (Telegram & friends):** too many items for a flat button grid —
render the list as **text** and offer **category buttons** that re-emit a filtered slice:
`[Scan] [Live tests ⚡] [Vet] [Track] [Share]`. Modifiers stay text. Degrades to the plain
text list when `capabilities.inlineButtons` is off.

**Decisions baked in:** *complete by construction* — the palette is the `_PRIMARY_MODES` set +
defaults, nothing hidden; every verb is grounded to a real flag in parens (drift-guard, same
spirit as `test_schema_grounding`); ⚡ vs ✅ reuses the Dashboard "Next" legend; niche CI/power
flags are pointed to `help` rather than dumped, to keep the palette readable.

**Implemented (F-045):** `clawseccheck/palette.py` holds the grounded registry (the single
source of truth) and `render_palette()`; the CLI emits it with **`--functions`** (Screen 12,
one level deeper than `--menu`'s Welcome). `tests/test_palette.py` enforces the drift-guard —
every `_PRIMARY_MODES` flag is either present in the palette or listed in
`palette.EXEMPT_FROM_PALETTE` (the container/internal flags `--menu`, `--functions`,
`--dashboard-findings`) — so the palette can't fall behind `cli.py`. `--ascii` folds ⚡→`(live)`
and drops emoji.

### 13. No-config / first-run onboarding — `~/.openclaw` missing or empty

The friendly landing when there is **nothing to audit** — don't render a wall of UNKNOWNs or a
scary F. Shown on the default human path only (`--json`/`--card` keep their machine/badge
contract). Read-only; fabricates no findings.

**When it fires (grounded in `cli._onboarding_reason`):**

- **missing** — the `--home` path (default `~/.openclaw`) does not exist.
- **empty** — the home is a bare directory (no entries at all).

It deliberately does **not** fire when anything is present — a readable config, an *unreadable*
config (perms), installed skills, or even junk. A present-but-unreadable `openclaw.json` keeps its
entry, so the dir isn't empty and the dashboard/error path surfaces the permission problem instead
of hiding it behind a welcome. A first run's benign `config not found` note is expected; any *other*
collection error (perms / parse / unreadable skill) also routes to the dashboard, not onboarding.

```
🦞 ClawSecCheck · welcome

I looked for an OpenClaw setup at ~/.openclaw, but there's nothing there.

ClawSecCheck audits an OpenClaw setup for security holes — I just need to find yours:
  • Default location:  ~/.openclaw
  • Config elsewhere?  re-run with  --home <path>
  • No OpenClaw yet?   install it, then run me again.

Once I can see it, say "check" and I'll run {N} security checks across your setup.
```

**Implemented (F-046):** `menu.render_onboarding()` renders it (reusing menu's `_ascii` fold, so
`--ascii` drops 🦞 and folds `•`→`-`); the home path is `report._sanitize`d before display.
`tests/test_onboarding.py` covers both reasons, the present-but-unreadable / junk exclusions, the
`--json` machine-contract, and ASCII purity. `mono`/`interactive` reuse the `text` body verbatim.
