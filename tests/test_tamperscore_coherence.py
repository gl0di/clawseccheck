"""C-163: pin the tamper sub-grade's hardcoded check-id literals to the catalog.

``tamperscore.TAMPER_CHECK_IDS`` is looked up by ``Finding.id``. If a catalog id is
renamed/renumbered, that ingredient silently vanishes from the sub-grade denominator with
no test-visible failure — the sub-grade keeps computing but measures less. This coherence
test turns such a rename into a CI failure instead (same spirit as test_version_coherence).
"""
from clawseccheck.catalog import CATALOG
from clawseccheck.tamperscore import TAMPER_CHECK_IDS

_CATALOG_IDS = {c.id for c in CATALOG}


def test_every_tamper_check_id_exists_in_catalog():
    missing = [cid for cid in TAMPER_CHECK_IDS if cid not in _CATALOG_IDS]
    assert not missing, (
        f"tamperscore.TAMPER_CHECK_IDS references ids not in the catalog: {missing} "
        f"— a rename silently drops the ingredient from the tamper sub-grade."
    )


def test_tamper_check_ids_are_unique():
    assert len(TAMPER_CHECK_IDS) == len(set(TAMPER_CHECK_IDS))
