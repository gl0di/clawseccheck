"""C-455 -- split into a builder / verdict-consumer package.

`adjudication.py`'s `tests/test_module_layout.py` line-budget exemption had been restated
three times since 2026-08-24 (~1,247 -> ~1,570 -> ~1,920 -> ~2,433 lines) with the split
filed but not done each time, and the file grew again to 2,478 lines before this task --
the guard's own message: "reconsider the split, do not just bump the number." The seam
already lived in the file: BUILDER (item construction,
evidence/target/host redaction, corroboration, `build_judge_packet`) versus VERDICT
CONSUMER (`--judged` / `--propose-ignore` / `--vet-judge-packet` parsing and escalation).
Checked mechanically before the cut: every top-level name each half defines was
cross-referenced against the other half's source, and the dependency is one-directional
(verdicts imports 10 names from builder; builder imports nothing from verdicts), so the
package needs no re-export cycle between the two leaves.

Layering, mirroring `checks/` and `monitordims/`:

    _builder.py    packet construction -- the judge-packet evidence sources, redaction,
                   corroboration, `build_judge_packet` / `render_judge_packet_json`
    _verdicts.py   verdict consumer -- `--judged`, `--propose-ignore`,
                   `--vet-judge-packet` / `--vet-judged`, pre-install prose attestation;
                   imports its 10 shared primitives from `_builder`
    __init__.py    this aggregator

**No `__all__` on this package or on any submodule** -- the `checks/` package's §3.1-a
rule, here for the same reason: 6 production modules and 31 test files import from
`clawseccheck.adjudication` directly, several by private name (`_emit_json`,
`_FN_PRONE_WARN_IDS`, `_CAP_LADDER`, `_parse_verdicts`, ...), so a narrow `__all__` would
hide every one of them. Every submodule name is re-exported below, underscore-prefixed
privates included -- `dir(clawseccheck.adjudication)` after this split is a superset of
`dir(clawseccheck.adjudication)` before it.
"""

from __future__ import annotations

# Names the pre-split adjudication.py also exposed, because they were its own top-level
# imports rather than something it defined -- e.g. `from clawseccheck.adjudication import
# _VERDICT_VALUES` (tests/test_sar.py) and `adj.redact(...)` (tests/test_b556_judge_packet_
# evidence.py) both reach into this module's *import* surface, not just its definitions.
# Re-declared here directly (both submodules already import their own subset for internal
# use; this is what keeps the AGGREGATOR'S namespace byte-for-byte what it was).
import hashlib  # noqa: F401
import json  # noqa: F401
import re  # noqa: F401
import sys  # noqa: F401
from dataclasses import replace as dc_replace  # noqa: F401
from pathlib import Path  # noqa: F401
from urllib.parse import urlparse  # noqa: F401

from ..baseline import fingerprint  # noqa: F401
from ..catalog import (  # noqa: F401
    ACTIONABLE_STATUSES,
    ATTESTED,
    BY_ID,
    FAIL,
    MEDIUM,
    UNKNOWN,
    WARN,
    Finding,
)
from ..logsafe import redact  # noqa: F401
from ..sar import _VERDICT_VALUES, build_sars  # noqa: F401
from ..skillast import analyze_env_auth_kwarg_exfil, analyze_python  # noqa: F401
from ..textnorm import normalize_for_scan  # noqa: F401

from ._builder import (  # noqa: F401
    _B452_ABBREV_WORDS,
    _B452_ANTECEDENT_RE,
    _B452_CONSEQUENT_WINDOW,
    _B452_EXEC_VERB_RE,
    _B452_FILE_HEADER_RE,
    _B452_INVOCATION_TARGET_LA,
    _B452_MANDATORY_RE,
    _B452_MAX_ITEMS_PER_SKILL,
    _B452_SENTENCE_END_RE,
    _CAP_LADDER,
    _CONFIG_BLIND_COLLAPSE_MIN,
    _CONFIG_BLIND_DETAIL_PREFIXES,
    _CONFIG_BLIND_REASON_TEXT,
    _CONFIG_PATH_RE,
    _CONFIG_PATH_ROOTS,
    _FALLBACK_EVIDENCE_RE,
    _FN_PRONE_WARN_IDS,
    _ID_QUESTIONS,
    _ID_QUESTIONS_WITH_DESTINATION,
    _ID_QUESTIONS_WITH_SUBSIGNAL,
    _LDH_HOST_RE,
    _LOC_SUFFIX_RE,
    _MAX_CAP_REASON_LEN,
    _MAX_FIELD_PATH_LEN,
    _MAX_HOST_LEN,
    _MAX_TARGET_LEN,
    _RECOVERED_TAINT_RULES,
    _RULE_QUESTIONS,
    _TARGET_ALLOWED_RE,
    _TARGET_COLLAPSE_RE,
    _URL_IN_EVIDENCE_RE,
    _VERDICT_SCHEMA,
    _attach_corroboration,
    _b452_consequent_span,
    _b452_containing_file,
    _b452_is_abbreviation_tail,
    _b62_items,
    _config_blind_collapsed_item,
    _config_blind_only_cause,
    _config_field_path,
    _config_field_paths,
    _corroboration_groups,
    _emit_json,
    _env_auth_kwarg_items,
    _evidence_locations,
    _gate_host,
    _gate_target,
    _is_borderline,
    _is_judgeable,
    _item_from_finding,
    _keyword_gated_trigger_items,
    _question_for,
    _recover_dropped_taint,
    _safe_destination_host,
    _target_from_evidence,
    _with_check_title,
    _with_documented_shape,
    build_bundle_template,
    build_judge_packet,
    caps_fired,
    render_judge_packet_json,
    run_state,
)

from ._verdicts import (  # noqa: F401
    _ESCALATION_TARGET,
    _MAX_VERDICTS_BYTES,
    _PRIORITY_BY_VERDICT,
    _VALID_VERDICTS,
    _VERDICT_CONTRACT_HINT,
    _VERDICT_RANK,
    _VET_ATTEST_IDS,
    _VET_ATTEST_NEW_FINDING_STATUS,
    _VET_ATTEST_QUESTIONS,
    _VET_ATTEST_TITLES,
    _annotate,
    _escalate_finding,
    _escalated_status,
    _note,
    _note_nothing_applied,
    _note_policy_refused_verdicts,
    _parse_verdicts,
    _payload_carries_content,
    _second_opinion,
    _verdicts_fingerprint_matches,
    _vet_attest_new_findings,
    _vet_attest_packet_items,
    _vet_pool,
    _vet_run_fingerprint,
    _vet_target_name,
    _vote_tally,
    build_ignore_proposals,
    build_vet_judge_packet,
    escalate_vet_output,
    render_ignore_proposals_json,
    render_judged_json,
    render_vet_judge_packet_json,
)
