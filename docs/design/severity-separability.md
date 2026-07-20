# Severity separability: why our FAIL-only recall is half of a static peer's

Design analysis. No code change is made by this document; it ends with one
recommendation, its measured cost, and the follow-up work it implies.

Measurement basis: SkillTrustBench (5,520 cases), via the external dev-only eval harness.
Two prediction sets already on disk were re-scored, and one new instrumented run over the
2,052 WARN cases was executed. Section 8 states exactly what came from where.

## 1. The finding

Both scanners expose a severity dial. Swept over the same corpus with the same binary
metric (positive = non-normal; FPR over the 1,643 `normal` cases):

| operating point | F1 | Precision | Recall | FPR |
|---|---|---|---|---|
| ours, WARN+FAIL | 0.8136 | 0.8381 | 0.7906 | 0.3603 |
| ours, **FAIL only** | 0.5341 | 0.9121 | **0.3776** | 0.0858 |
| static peer, CRITICAL+ | 0.6394 | 0.9422 | 0.4839 | 0.0700 |
| static peer, HIGH+ (its own `is_safe`) | 0.7803 | 0.9278 | **0.6732** | 0.1236 |
| static peer, MEDIUM+ | 0.8191 | 0.8694 | 0.7743 | 0.2745 |
| static peer, LOW+ | 0.8237 | 0.8606 | 0.7898 | 0.3019 |

Two readings, both unflattering:

- **At matched precision (~0.92)** the peer recalls 0.6732 against our 0.3776 — 1.78x
  more of the real malware at the same false-alarm cost.
- **At matched recall (~0.790)** the peer's LOW+ point has precision 0.8606 / FPR 0.3019
  against our 0.8381 / 0.3603. Its curve is outside ours at *both* ends.

The headline "0.8136 vs 0.7803" only appears when our loosest setting is compared to
their strictest. It is not a lead and must not be published as one.

### What any WARN-promotion rule must achieve

Our two operating points are the ends of a segment: FAIL-only is (P 0.9121, R 0.3776);
promoting *every* WARN reproduces the WARN+FAIL point (P 0.8381, R 0.7906). Any
"promote some WARNs" rule lands between them, and where depends on the purity of the
subset it promotes.

Measured composition of the 2,052 WARN cases: 1,230 malicious, 371 suspicious, 451
normal. Gold-positive base rate among WARNs = 1,601/2,052 = **0.780**.

Derived from those measured counts:

- **Oracle ceiling.** Promoting exactly the 1,601 gold-positive WARNs gives
  P 3,065/3,206 = 0.956 at R 0.7906. No rule of this shape can beat that.
- **The bar to match the peer.** To reach R 0.6732 (2,610 TP) while holding P >= 0.9278,
  a rule must promote 1,146 of the 1,601 gold-positive WARNs (71.6%) while promoting at
  most 62 of the 451 normal WARNs (13.7%) — a promoted subset that is **~94.9%
  gold-positive**, against a base rate of 78.0%.

## 2. Q1 — where the recall lives: the partition

This is the load-bearing measurement. Of the malicious cases we catch only at WARN, how
many carried a signal that *was* FAIL-capable and got downgraded, versus never had one?

`check_installed_skills` collects evidence into named buckets, and each bucket is either

- **Class D (downgraded)** — the signal is appended to the FAIL-capable `crit`/`high`
  lists everywhere *except* when a specific down-rank predicate fires (Section 3.2), or
- **Class N (never FAIL-capable)** — no path to `crit`/`high` exists; the source says so
  ("WARN-first", "never an automatic FAIL", "never FAIL on their own").

Because the verdict chain is first-match-wins, counting only the *winning* bucket would
undercount Class D. The instrumented run therefore records the full bucket census, so a
downgraded signal is counted even when a higher-ranked bucket won the verdict.

Measured over all 2,052 WARN cases:

| gold class | n | Class D (downgraded) | Class N (never FAIL-capable) |
|---|---|---|---|
| malicious | 1,230 | **33 (2.68%)** | **1,197 (97.32%)** |
| suspicious | 371 | 8 (2.16%) | 363 (97.84%) |
| normal | 451 | 24 (5.32%) | 427 (94.68%) |

Class D among malicious WARNs, by originating gate: persistence down-ranks 27,
notification-host down-rank 4, installer-fetch down-rank 3, test-fixture/prohibition
content down-rank 0.

**This settles the calibration-vs-detection question, and not in the direction the
framing assumed.** 97.3% of the malicious cases we catch only at WARN never had a
FAIL-capable signal at all. The nine down-rank predicates are not where the recall is.

The second row is the one worth pausing on: **the downgrade gates fire on benign skills
(5.32%) at roughly twice the rate they fire on malicious ones (2.68%)**. They are doing
their job. Relaxing them would cost more precision than it buys recall — confirmed
directly as option O2 in Section 5.

So the recall is not being downgraded. It is sitting in signals that the engine was
never willing to fail on, in a structure that cannot combine them.

## 3. Q2 — the gates that produce a WARN instead of a FAIL

Line references are to the working tree at version 3.54.0.

### 3.1 The structural gate: one finding, first match wins

`vet_skill` (`clawseccheck/checks/_vet.py:2668`) returns a **single** `Finding`.
`check_installed_skills` (`clawseccheck/checks/_vet.py:1808`) reaches its verdict through
a flat ordered if-chain of `return` statements — the first non-empty bucket wins, every
other bucket is discarded:

| rank | line | bucket | verdict |
|---|---|---|---|
| 1 | `_vet.py:2223` | `crit` | FAIL |
| 2 | `_vet.py:2237` | `high` | FAIL |
| 3 | `_vet.py:2252` | `parse_error_paths` | UNKNOWN |
| 4 | `_vet.py:2272` | `limit_hits` (+ `padding_anomalies`) | WARN / UNKNOWN |
| 5 | `_vet.py:2305` | `warns_install_curl` | WARN |
| 6 | `_vet.py:2325` | `warns_env_exfil` | WARN |
| 7 | `_vet.py:2345` | `warns_host_exfil` | WARN |
| 8 | `_vet.py:2368` | `warns_curl_dropper` | WARN |
| 9 | `_vet.py:2387` | `warns_timebomb` | WARN |
| 10 | `_vet.py:2406` | `warns_shell_injection` | WARN |
| 11 | `_vet.py:2426` | `warns_insecure_tempfile` | WARN |
| 12 | `_vet.py:2448` | `warns_js` | WARN |
| 13 | `_vet.py:2466` | `warns_content` | WARN |
| 14 | `_vet.py:2484` | `warns_notify_host` | WARN |
| 15 | `_vet.py:2503` | `_persist_warn` | WARN |
| 16 | `_vet.py:2518` | `warns_local_exfil` | WARN |
| 17 | `_vet.py:2561` | `warnings` (mismatch/polyglot/binary) | WARN |
| 18 | `_vet.py:2571` | `warns_unpinned` | WARN |
| 19 | `_vet.py:2601` | `warns_squat` | WARN |

**This is the most consequential design fact in the engine.** There is no accumulation: a
skill tripping one weak bucket and a skill tripping five different ones return the
identical WARN, at the identical severity, carrying only the winning bucket's evidence.

The ring merge has the same property. `_VET_MERGE_RANK` (`_vet.py:2638`) picks the single
highest-ranked finding across `{B13} ∪ ring` (40 ring checks, `_vet.py:3222`), so N ring
WARNs plus a B13 WARN still yield one WARN. Measured: of the 2,052 WARN cases, **975 have
a ring check rather than B13 as the primary verdict** — the ring is not a side channel,
it decides nearly half the WARN verdicts, and its corroboration is discarded too.

### 3.2 The explicit down-rank predicates (Class D)

Each takes a signal that would otherwise land in `crit`/`high` and routes it to a WARN
bucket. Section 2 measures their combined contribution at 2.68% of malicious WARNs.

| # | site | signal | down-rank condition |
|---|---|---|---|
| D1 | `_vet.py:1904` | download-and-run a package over http | `_under_install_heading` / `_under_defensive_heading` |
| D2 | `_vet.py:1886` | base64-decode piped to exec | `_pos_in_test_fixture_file` |
| D3 | `_vet.py:1895` | excessive-agency auto-approve directive | `_agency_prohibition_governs` |
| D4 | `_vet.py:1940` | runtime-external-fetch (AST05) | own host, install heading, credential-acquisition prose, or `_fetch_prohibition_governs` |
| D5 | `_vet.py:1966` | pipe-to-shell from a non-reputable host | own host, install heading, or test fixture |
| D6 | `_vet.py:1857` | Telegram/Discord exfil host | no secret/file-read taint reaches the request |
| D7 | `_vet.py:2078` | cron/startup persistence | reputable service, disclosed watchdog, or test fixture |
| D8 | `_vet.py:2086` | `authorized_keys` persistence | key content is not a literal |
| D9 | `_vet.py:2100` | agent-config write | skill declares that target as its purpose **and** nothing else flagged it **and** no dangerous payload |

D9 is the only gate that already conditions on corroboration (`_has_other_signal`). The
other eight decide on their predicate alone, regardless of what else the skill did.

**Which are too conservative on evidence? On this corpus, none of them.** The measured
2.68%/5.32% split says they are net-correct. That is a real result and it should stop the
recurring instinct to reopen them.

### 3.3 The WARN-by-construction ceilings (Class N)

These have no path to FAIL at any evidence strength — each a documented calibration
decision: `warns_env_exfil` (`_vet.py:2325`), `warns_host_exfil` (`_vet.py:2345`),
`warns_curl_dropper` (`_vet.py:2368`), `warns_timebomb` (`_vet.py:2387`),
`warns_shell_injection` (`_vet.py:2406`), `warns_insecure_tempfile` (`_vet.py:2426`),
`warns_js` (`_vet.py:2448`), `warns_local_exfil` (`_vet.py:2518`).

Note the shape of that list. `warns_env_exfil` co-occurring with `warns_timebomb` is
"a secret reaches the network, behind a date gate" — a sleeper exfiltrator — and today
that returns the same single WARN as an unpinned dependency. The information is present;
the architecture has nowhere to put it.

## 4. Q3 — does the confidence field already carry the answer?

**No. It is a per-check constant, and where it appears to separate, per-check identity
does the same job three times better.**

### 4.1 It is a constant by construction

`_custom` (`clawseccheck/checks/_shared.py:797`) — the constructor used by *every*
`check_installed_skills` return path — sets `confidence=m.confidence`, the static
`CheckMeta` value, with no per-finding override. B13 declares `confidence="MEDIUM"`
(`clawseccheck/catalog.py:233`). So every B13 finding, from any of the 19 buckets,
carries `MEDIUM`. `pass_confidence` is documented as meaningful only for PASS
(`clawseccheck/catalog.py:2372`) and `_custom` never sets it.

### 4.2 Measured over 2,052 WARN cases

`pass_confidence` was `None` on **2,052 of 2,052** — it carries nothing on this path,
exactly as the source predicts.

| stratum | n | gold-positive |
|---|---|---|
| primary confidence MEDIUM | 1,866 | 77.3% |
| primary confidence HIGH | 186 | 85.5% |
| ring confidence MEDIUM | 868 | 87.4% |
| ring confidence HIGH | 126 | 96.8% |
| ring confidence LOW | 8 | 100.0% |

There *is* a separation — 77.3% vs 85.5% on the primary, 87.4% vs 96.8% on the ring. But
it is not evidence strength. Confidence is a per-check constant, so "HIGH-confidence
WARN" is a synonym for "one of the few HIGH-confidence checks fired". Compare what the
check identity itself yields (Section 5.2): B98 99.7%, B13 68.2% — a 31.5-point spread
against confidence's 8.2. **Confidence is a lossy proxy for check identity, and a
promotion rule keyed on it would be a worse-specified version of a rule keyed on the
check.** Promotion-by-confidence is off the table, and no work should be spent adding
per-finding confidence plumbing to make it available.

This is the null result the analysis was asked to report if it found one.

## 5. Q4 — candidate options, with measured cost

### 5.1 What does discriminate: corroboration count

The engine's discarded signal is the one that works. Over the 2,052 WARN cases, counting
distinct check IDs that fired:

| distinct checks firing | n | malicious | suspicious | normal | gold-positive |
|---|---|---|---|---|---|
| 1 | 1,149 | 557 | 253 | 339 | 70.5% |
| 2 | 635 | 434 | 103 | 98 | 84.6% |
| 3 | 209 | 180 | 15 | 14 | 93.3% |
| 4 | 49 | 49 | 0 | 0 | 100.0% |
| 5 | 10 | 10 | 0 | 0 | 100.0% |

Monotonic, and it reaches purity: **every one of the 59 WARN cases where four or more
independent checks agreed was genuinely non-normal.** This is precisely the quantity
`_VET_MERGE_RANK` throws away.

### 5.2 Per-check gold-positive rate (WARN cases, primary check)

| primary | n | gold-positive |
|---|---|---|
| B13 | 1,077 | 68.2% |
| B98 | 373 | **99.7%** (1 normal) |
| B63 | 186 | 85.5% |
| B62 | 182 | 94.0% |
| B58 | 58 | 87.9% |
| B65 | 57 | 61.4% |

### 5.3 Measured options

Each row re-scores the FAIL-only operating point over all 5,520 cases with that promotion
rule applied to the WARN set. Baseline FAIL set = 1,605 (1,464 TP, 141 FP).

| option | FAIL set | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| **O0** do nothing | 1,605 | 0.9121 | 0.3776 | 0.5341 | 0.0858 |
| **O1** promote every WARN (bound, not a proposal) | 3,657 | 0.8381 | 0.7906 | 0.8136 | 0.3603 |
| **O2** promote Class D (relax the down-rank gates) | 1,670 | 0.9012 | 0.3882 | 0.5426 | 0.1004 |
| **O3** promote >= 2 distinct checks | 2,508 | 0.8991 | 0.5816 | 0.7063 | 0.1540 |
| **O3** promote >= 3 distinct checks | 1,873 | **0.9172** | 0.4431 | 0.5976 | 0.0943 |
| **O3** promote >= 4 distinct checks | 1,664 | 0.9153 | 0.3928 | 0.5497 | 0.0858 |
| **O3b** promote >= 3 total signals (checks + buckets) | 1,989 | 0.9140 | 0.4689 | 0.6198 | 0.1041 |
| **O5** promote B98-primary | 1,978 | 0.9282 | 0.4736 | 0.6272 | 0.0864 |
| **O5** promote the shell-injection bucket | 1,726 | 0.9171 | 0.4083 | 0.5651 | 0.0870 |
| **O6** O3(>= 3 checks) **or** B98-primary | 2,246 | **0.9305** | **0.5391** | 0.6827 | 0.0949 |
| *(reference)* static peer HIGH+ | — | 0.9278 | 0.6732 | 0.7803 | 0.1236 |

Readings:

- **O2 is refuted.** Relaxing the down-rank gates trades 0.011 precision and +0.015 FPR
  for 0.011 recall. It is the intuitive fix and it is the wrong one — as Section 2
  predicted.
- **O3 at >= 3 checks strictly improves precision** (0.9121 → 0.9172) *while* raising
  recall (0.3776 → 0.4431). Cost is +0.0085 FPR, i.e. 141 → 155 benign FAILs on this
  corpus.
- **O6 exceeds the peer's precision (0.9305 vs 0.9278) at a lower FPR (0.0949 vs 0.1236)**
  and narrows the recall gap from 1.78x to 1.25x. It does not close it. Per the
  honest-labelling rule: this narrows the gap, it does not eliminate it.

### 5.4 The benchmark-fitting hazard in O5/O6 — read before adopting

O5's numbers are the best in the table and its risk is the highest. B98 is "invokes a
code-execution primitive but declares no allowed-tools/tools manifest". This corpus
defines `normal` as *no attack **and** no vulnerability*, which makes "no manifest"
almost definitionally non-normal here — hence 99.7%. On a real fleet, a large fraction
of perfectly benign skills ship no manifest and call `subprocess`. **Promoting B98 to
FAIL is a plausible mass-false-FAIL on real skills and would breach the zero-false-FAIL
rule.** The same caution applies to the shell-injection bucket row (100% positive on this
corpus because insecure coding *is* the label).

O3 does not have this problem: it promotes no individual signal, only the agreement of
three independent checks. It is an evidence-combination rule, not a threshold tweak, and
is far less likely to be corpus-specific — but it still needs an independent adversarial
pass against real skills before it ships.

## 6. Q5 — the do-nothing option

Stated at full strength, not as a foil.

**For:**

1. **The FAIL bar is a promise, not a tuning parameter.** No-false-FAIL is why a user can
   act on a FAIL without triaging it. Every promotion rule spends precision against that
   promise, and spends it on a corpus whose `normal` is stricter than a real fleet.
2. **The benchmark is not the user.** The board's metric merges malicious and suspicious
   into one positive class, rewarding exactly the behaviour our ladder exists to avoid:
   calling a maybe a definitely. Our WARN is not a miss on the product surface — the user
   sees it, and the borderline-adjudication path exists to route those cases to a judge
   rather than to a louder regex.
3. **The gap at matched recall is small.** At R ~0.790 we are 0.022 precision behind.
   The 1.78x figure lives only at the strict end, where our conservatism is deliberate.
4. **We are not tuned to this taxonomy; the peers may be.** Section 5.4 shows how easily
   this corpus rewards a rule that would misfire in the field.

**Against:** the structural finding in Section 3.1 is not a threshold choice, it is an
architectural inability. Section 5.1 measures the cost precisely: the corroboration count
separates 70.5% → 100% monotonically, and the engine discards it. "Five independent
checks agree" and "one weak check fired" are different evidentiary situations and the
engine cannot represent the difference. That is a defect on its own terms, and it would
remain one if this benchmark did not exist.

**Both are true.** The threshold may be correctly conservative while the evidence model
underneath it is lossy. That distinction is the recommendation.

## 7. Recommendation

**Adopt the accumulation architecture (O3), not a threshold change. Keep the down-rank
gates exactly as they are. Do not adopt B98 promotion.**

Concretely, in priority order:

1. **Make corroboration representable.** Today `check_installed_skills` returns one
   finding from a first-match-wins chain and `_VET_MERGE_RANK` collapses the ring to a
   single winner. The verdict should be computed from the *set* of firing signals, with
   the non-winning buckets and ring findings retained as corroboration rather than
   discarded. This is the load-bearing change; every option in Section 5.3 except O2 and
   O5 depends on it.
2. **Set the FAIL bar at >= 3 distinct corroborating checks**, in addition to the existing
   `crit`/`high` paths.

   **Measured cost: precision 0.9121 → 0.9172 (improves), recall 0.3776 → 0.4431,
   FPR 0.0858 → 0.0943 — i.e. 141 → 155 benign FAILs on this corpus, +14.** F1 0.5341 →
   0.5976.

3. **Do not touch the nine down-rank predicates.** Measured as net-correct (Section 2);
   O2 measured as a losing trade (Section 5.3).
4. **Do not spend work on per-finding confidence.** Measured as a lossy proxy for check
   identity (Section 4).
5. **Treat B98/O6 as a separate, higher-risk proposal** requiring an independent
   adversarial pass against real skills, not fixtures, before it is considered. Its
   corpus numbers are the best available and its field risk is the worst.

**Honest labelling.** O3 narrows the precision-matched recall gap from 0.3776-vs-0.6732
(1.78x) to 0.4431-vs-0.6732 (1.52x). It does not close it, and this document does not
claim a path that does. Roughly half the remaining gap sits in Class N single-signal
cases where one weak detector fired alone — closing those is new detection work, not
calibration, and is out of scope here.

## 8. Measurement provenance

- The Section 1 sweep was recomputed from the two prediction sets already on disk in the
  eval harness run directories (ours at v3.53.0; the peer's static-only run). Both
  reproduce the published summary exactly, including our confusion matrix (normal
  1051/451/141, suspicious 494/371/149, malicious 318/1230/1315) and the 141 benign
  FAILs. The peer's CRITICAL+ and LOW+ rows are new here, derived from the `max_severity`
  field its harness already records — no re-run.
- WARN population counts (2,052 = 1,230 + 371 + 451) are counted from the same artifacts.
- Section 3 line references and Section 4.1 were read from the working tree at version
  3.54.0.
- Sections 2, 4.2 and 5 required per-case evidence-bucket detail, which the stored
  predictions do not carry (id, mapped label and overall status only). A new instrumented
  run over all 2,052 WARN cases was executed against a fixed snapshot of the tree at
  version 3.54.0. The snapshot adds exactly one 27-line statement recording the bucket
  census on the context object before the verdict chain; no verdict logic is touched and
  the production tree is unmodified.
- **Drift control:** all 2,052 cases that were WARN at v3.53.0 were still WARN on the
  v3.54.0 snapshot — zero drift — so the Section 5.3 option rows can be composed against
  the v3.53.0 baseline FAIL set without a full re-run.

## 9. Limits of this analysis

- The Section 5.3 rows re-score the FAIL threshold by *composing* promoted WARN cases onto
  the v3.53.0 FAIL set. The PASS and FAIL populations were not themselves re-run at
  v3.54.0; the zero-drift result above is evidence for, but not proof of, their stability.
- Everything here is measured on one corpus whose `normal` label is stricter than a real
  fleet. Section 5.4 shows this is not a formality — it is why the best-scoring option is
  the one to be most suspicious of.
- No real-fleet verification was performed under this analysis. Any option adopted from
  Section 5.3 must clear the zero-false-FAIL bar against real configs before it ships;
  that verification is implementation work, not analysis work, and is deliberately left
  to the follow-up.
- Two ring-layer modules changed in the tree after the snapshot was taken. The measurement
  is self-consistent at a fixed point but is not identical to the branch tip.
