"""The five-layer ledger: what a full audit can actually vouch for.

A grade is a claim about the *subject* (an agent setup), and the subject is only as
well understood as the layers that actually ran against it. This module is the single
place that names those layers, the statuses a layer can be in, and the ledger type that
refuses to let one go unaccounted for. Pure stdlib, no deps — a leaf: it imports nothing
from ``clawseccheck`` itself, so every other module can depend on it without risking a
cycle (CLAUDE.md §3 dependency flow).

======================  ============================================================
layer                   what it covers
======================  ============================================================
static                  the config/manifest audit (the checks engine itself)
installed_sweep         installed skills/plugins scanned on disk (``--vet-all`` etc.)
logs_trajectories       trajectory/audit-trail/behavioral log analysis
self_report             the audited agent's own attestation
live_behaviour          active self-test / red-team / canary probes against a live agent
======================  ============================================================
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

# ── layer identity ───────────────────────────────────────────────────────────

LAYER_STATIC = "static"
LAYER_INSTALLED_SWEEP = "installed_sweep"
LAYER_LOGS_TRAJECTORIES = "logs_trajectories"
LAYER_SELF_REPORT = "self_report"
LAYER_LIVE_BEHAVIOUR = "live_behaviour"

#: Canonical order every ledger view (missing/not_checked/report) preserves.
LAYER_ORDER = (
    LAYER_STATIC,
    LAYER_INSTALLED_SWEEP,
    LAYER_LOGS_TRAJECTORIES,
    LAYER_SELF_REPORT,
    LAYER_LIVE_BEHAVIOUR,
)

# ── layer status ─────────────────────────────────────────────────────────────

STATUS_RAN = "ran"
STATUS_SKIPPED = "skipped"  # the operator narrowed the run (e.g. --fast)
STATUS_REFUSED = "refused"  # the user declined this layer
STATUS_UNAVAILABLE = "unavailable"  # no live agent / nothing to ask, by construction
STATUS_ERROR = "error"  # the layer tried and blew up
# Kept only so pipeline.py keeps its existing vocabulary (it already used this exact
# string for a phase that never got its turn before the deadline) — it is a valid
# layer status too, not a leftover to delete.
STATUS_NOT_REACHED = "not_reached"

LAYER_STATUSES = frozenset({
    STATUS_RAN, STATUS_SKIPPED, STATUS_REFUSED, STATUS_UNAVAILABLE,
    STATUS_ERROR, STATUS_NOT_REACHED,
})

#: Every status except STATUS_RAN — a layer in one of these cannot vouch for its subject.
INCOMPLETE_LAYER_STATUSES = frozenset(LAYER_STATUSES - {STATUS_RAN})


@dataclass(frozen=True)
class LayerState:
    status: str
    #: What this layer did NOT cover, in plain English, e.g.
    #: "79 of 132 log sinks not read". Empty when the layer covered its subject.
    not_reached: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in LAYER_STATUSES:
            raise ValueError(
                f"unknown layer status {self.status!r}; must be one of "
                f"{sorted(LAYER_STATUSES)}"
            )
        # Normalise to a tuple so a caller who passes a list does not silently produce an
        # unhashable "frozen" state that also compares unequal to a tuple-built twin.
        if not isinstance(self.not_reached, tuple):
            object.__setattr__(self, "not_reached", tuple(self.not_reached))


@dataclass(frozen=True)
class LayerLedger:
    """One :class:`LayerState` per layer in :data:`LAYER_ORDER` — no more, no fewer.

    A ledger that silently omits a layer would let ``complete`` lie about a subject
    it never actually looked at, which is exactly the failure mode this module exists
    to close off. Construction is where that gets enforced, once, so every reader of
    an already-built ``LayerLedger`` can trust it unconditionally.
    """

    states: MappingProxyType[str, LayerState]

    def __post_init__(self) -> None:
        given = dict(self.states)
        unknown = sorted(set(given) - set(LAYER_ORDER))
        if unknown:
            raise ValueError(f"unknown layer name(s): {unknown}; expected one of {LAYER_ORDER}")
        missing = [layer for layer in LAYER_ORDER if layer not in given]
        if missing:
            raise ValueError(
                f"LayerLedger is missing layer(s): {missing} — all five of {LAYER_ORDER} "
                "must be present"
            )
        # Frozen + hashable-friendly: normalise into a MappingProxyType so the dataclass
        # never exposes a mutable dict, without needing __hash__/__eq__ machinery of our
        # own. object.__setattr__ is required because the dataclass is frozen.
        object.__setattr__(self, "states", MappingProxyType(dict(given)))

    def status(self, layer: str) -> str:
        return self.states[layer].status

    @property
    def complete(self) -> bool:
        """True only when every one of the five layers actually ran."""
        return all(self.states[layer].status == STATUS_RAN for layer in LAYER_ORDER)

    @property
    def missing(self) -> tuple[str, ...]:
        """Layer names whose status is not ``ran``, in :data:`LAYER_ORDER`."""
        return tuple(
            layer for layer in LAYER_ORDER if self.states[layer].status != STATUS_RAN
        )

    @property
    def not_checked(self) -> tuple[str, ...]:
        """Union of every layer's ``not_reached``, in :data:`LAYER_ORDER`, de-duplicated,
        order-stable."""
        seen: set[str] = set()
        out: list[str] = []
        for layer in LAYER_ORDER:
            for item in self.states[layer].not_reached:
                if item not in seen:
                    seen.add(item)
                    out.append(item)
        return tuple(out)
