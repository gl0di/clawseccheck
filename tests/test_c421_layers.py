"""CLAWSECCHECK-C-421 — the five-layer ledger (clawseccheck/layers.py).

Stdlib-only, offline. Covers LayerState/LayerLedger validation and derived views, the
leaf-module import-graph guard, and that pipeline.py's re-export of the status
constants actually points at the same objects layers.py defines.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from clawseccheck import layers, pipeline
from clawseccheck.layers import (
    INCOMPLETE_LAYER_STATUSES,
    LAYER_INSTALLED_SWEEP,
    LAYER_LIVE_BEHAVIOUR,
    LAYER_LOGS_TRAJECTORIES,
    LAYER_ORDER,
    LAYER_SELF_REPORT,
    LAYER_STATIC,
    LAYER_STATUSES,
    STATUS_ERROR,
    STATUS_NOT_REACHED,
    STATUS_RAN,
    STATUS_REFUSED,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
    LayerLedger,
    LayerState,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
LAYERS_PY = REPO_ROOT / "clawseccheck" / "layers.py"


def _all_ran_states() -> dict:
    return {layer: LayerState(status=STATUS_RAN) for layer in LAYER_ORDER}


def test_all_ran_is_complete_and_nothing_missing() -> None:
    ledger = LayerLedger(states=_all_ran_states())
    assert ledger.complete is True
    assert ledger.missing == ()


@pytest.mark.parametrize(
    "status",
    [STATUS_SKIPPED, STATUS_REFUSED, STATUS_UNAVAILABLE, STATUS_ERROR, STATUS_NOT_REACHED],
)
def test_each_non_ran_status_breaks_complete(status: str) -> None:
    states = _all_ran_states()
    states[LAYER_SELF_REPORT] = LayerState(status=status)
    ledger = LayerLedger(states=states)
    assert ledger.complete is False
    assert ledger.missing == (LAYER_SELF_REPORT,)


def test_missing_is_ordered_by_layer_order_not_insertion_order() -> None:
    # Deliberately scrambled insertion order, and not all five present-but-scrambled —
    # dict preserves insertion order in Python, so this would fail if LayerLedger ever
    # iterated self.states instead of LAYER_ORDER.
    states = {
        LAYER_LIVE_BEHAVIOUR: LayerState(status=STATUS_SKIPPED),
        LAYER_STATIC: LayerState(status=STATUS_RAN),
        LAYER_SELF_REPORT: LayerState(status=STATUS_ERROR),
        LAYER_INSTALLED_SWEEP: LayerState(status=STATUS_RAN),
        LAYER_LOGS_TRAJECTORIES: LayerState(status=STATUS_UNAVAILABLE),
    }
    ledger = LayerLedger(states=states)
    assert ledger.missing == (
        LAYER_LOGS_TRAJECTORIES, LAYER_SELF_REPORT, LAYER_LIVE_BEHAVIOUR,
    )


def test_not_checked_unions_orders_and_dedupes() -> None:
    states = _all_ran_states()
    states[LAYER_STATIC] = LayerState(
        status=STATUS_RAN, not_reached=("dup", "static-only"),
    )
    states[LAYER_INSTALLED_SWEEP] = LayerState(
        status=STATUS_SKIPPED, not_reached=("dup", "sweep-only"),
    )
    states[LAYER_LIVE_BEHAVIOUR] = LayerState(
        status=STATUS_UNAVAILABLE, not_reached=("live-only",),
    )
    ledger = LayerLedger(states=states)
    # LAYER_ORDER = static, installed_sweep, logs_trajectories, self_report, live_behaviour
    assert ledger.not_checked == ("dup", "static-only", "sweep-only", "live-only")


def test_status_accessor() -> None:
    ledger = LayerLedger(states=_all_ran_states())
    assert ledger.status(LAYER_STATIC) == STATUS_RAN


def test_ledger_missing_a_layer_raises_value_error() -> None:
    states = _all_ran_states()
    del states[LAYER_LIVE_BEHAVIOUR]
    with pytest.raises(ValueError):
        LayerLedger(states=states)


def test_ledger_with_unknown_layer_name_raises_value_error() -> None:
    states = _all_ran_states()
    states["not_a_real_layer"] = LayerState(status=STATUS_RAN)
    with pytest.raises(ValueError):
        LayerLedger(states=states)


def test_layer_state_with_bogus_status_raises_value_error() -> None:
    with pytest.raises(ValueError):
        LayerState(status="totally-made-up")


def test_layer_statuses_and_incomplete_set_are_consistent() -> None:
    assert LAYER_STATUSES == {
        STATUS_RAN, STATUS_SKIPPED, STATUS_REFUSED, STATUS_UNAVAILABLE,
        STATUS_ERROR, STATUS_NOT_REACHED,
    }
    assert INCOMPLETE_LAYER_STATUSES == LAYER_STATUSES - {STATUS_RAN}
    assert STATUS_RAN not in INCOMPLETE_LAYER_STATUSES


def test_layers_module_is_a_true_leaf() -> None:
    """Import-graph guard: layers.py must import nothing from clawseccheck itself —
    no relative import, no absolute `clawseccheck.*` import. Parsed with ast rather
    than asserted in prose, so a future edit can't quietly grow a cycle."""
    tree = ast.parse(LAYERS_PY.read_text(encoding="utf-8"))
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                offenders.append(f"relative import (level={node.level}): {node.module}")
            elif node.module and node.module.split(".")[0] == "clawseccheck":
                offenders.append(f"absolute clawseccheck import: {node.module}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "clawseccheck":
                    offenders.append(f"absolute clawseccheck import: {alias.name}")
    assert not offenders, (
        "clawseccheck/layers.py must stay a leaf (no import from clawseccheck itself): "
        + ", ".join(offenders)
    )


def test_pipeline_reexports_the_same_status_objects() -> None:
    """pipeline.py no longer defines its own STATUS_* strings; it re-exports layers.py's.
    Since these are interned str literals identity (`is`) holds too, but equality is the
    contract that actually matters."""
    assert pipeline.STATUS_RAN is layers.STATUS_RAN
    assert pipeline.STATUS_SKIPPED is layers.STATUS_SKIPPED
    assert pipeline.STATUS_NOT_REACHED is layers.STATUS_NOT_REACHED
    assert pipeline.STATUS_UNAVAILABLE is layers.STATUS_UNAVAILABLE
    assert pipeline.STATUS_ERROR is layers.STATUS_ERROR
