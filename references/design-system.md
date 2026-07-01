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
skeleton**. Box-drawing + "type 1-4" is a *terminal* assumption that breaks on Telegram.

The current `SKILL.md` Dashboard (Step 3) already reflects this — it uses emoji +
indentation + markdown, **not** box-art. The design system formalizes that instinct.

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
| 3 | **Dashboard** (A–F audit) | guided + CLI | Step 3 / `audit.py` | ▢ next |
| 4 | **What-changed** (diff vs last) | guided + CLI | `--monitor` | ▢ todo |
| 5 | **Vet verdict** (skill / MCP supply-chain) | guided + CLI | `--vet` / `--vet-mcp` | ▢ todo |
| 6 | **Self-test** (canary · red-team · dry-run) | guided + CLI | `--self-test` | ▢ todo |
| **Reusable blocks** ||||
| 7 | **Finding card** (one risk) | both | inside 3/4 | ▢ stub |
| 8 | **Fix prompts** (copy-paste) | both | `--fix` | ▢ todo |
| 9 | **Notices** (freshness / update / private) | both | inline | ▢ stub |
| **Artifacts** ||||
| 10 | **Badge / card** (shareable) | CLI | `--card` | ▢ todo |
| 11 | **HTML report** | CLI | `--html` | ▢ todo |
| **Discovery & onboarding** ||||
| 12 | **Menu / All functions** (capability palette) | guided | "menu" / `?` / `[More…]` | ✅ drawn |
| 13 | **No-config / first-run** (`~/.openclaw` missing) | guided + CLI | empty/missing home | ▢ todo |
| 14 | **Update flow** (check → result → offer) | guided | "update" / `[Check update]` | ▢ todo |

> Also pending: a **clean-result Dashboard** variant (Grade A / 0 issues) — Component 3 must
> cover the "all good" state, not just the vulnerable case.

### Layer 2 — Render profiles

One component → up to three renderings. **`text` is the contract every screen MUST satisfy;**
`mono` and `interactive` are progressive enhancements, never required to operate.

- **`text` — baseline, ALL channels.** Markdown headers + emoji severity + numbered choices
  ("say 1 / go") + indentation. **No box-art, no color, no buttons.** If a screen works
  here, it works everywhere.
- **`mono` — terminal / TUI enhancement.** May add box-drawing, aligned columns, ANSI color.
  `--ascii` strips emoji + box back toward `text`.
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

### 2. Next-actions — post-result menu · guided Step 4
_Stub. After the Dashboard: what to do next (fixes, deeper, vet, monitor). Reuses Choices[]._

### 3. Dashboard — audit result · guided Step 3
_Stub (next). A–F score banner + Lethal-Trifecta line + ranked plain-language Findings[].
Source: `audit.py --json`._

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

### 11. HTML report — `--html`
_Stub. Standalone HTML report variant._

### 12. Menu / All functions — capability palette · "menu" / `?` / `[More…]`

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
  Deeper scan       "deeper" / "2"    + facts config can't show; I self-report them (--ask→--attest)
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

**Decisions baked in:** *complete by construction* — the palette is the 21 `_PRIMARY_MODES` +
defaults, nothing hidden; every verb is grounded to a real flag in parens (drift-guard, same
spirit as `test_schema_grounding`); ⚡ vs ✅ reuses the Dashboard "Next" legend; niche CI/power
flags are pointed to `help` rather than dumped, to keep the palette readable.
