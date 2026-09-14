"""CLAWSECCHECK-C-521 — `--sbom --format cyclonedx|spdx` and `--save-sbom-run` /
`--sbom-diff RUN_ID1 RUN_ID2`.

Both new export formats are a PRESENTATION-time transform of the exact same
`build_sbom(ctx)` inventory `--sbom`'s native JSON already renders (sbom.py) — never a
second scan. Each component's content hash reuses the identical input text
`monitor.py`'s own `_h()` hashes for the native format's (deliberately truncated,
16-char) hash — just without the truncation, since CycloneDX/SPDX's standard hash
fields validate against a full-length digest for their declared algorithm and a
16-char value would not itself validate as real SHA-256.

License is never asserted (nothing collected carries license data for a locally
installed skill/MCP-server/plugin) — CycloneDX omits the optional `licenses` key
entirely rather than fabricate a value; SPDX uses its own standard `"NOASSERTION"`,
which is precisely Golden Rule #4's "report UNKNOWN, never guess" in that format's own
vocabulary.

`--sbom-diff` is a SEPARATE store/diff from `--diff` (CLAWSECCHECK-C-524's own
`runstore.py`/`--save-run`) — `runstore.diff_runs()` is hard-coded to Finding fields
(id/status/detail/severity/title) throughout, and an SBOM component (name/version/hash,
no severity or status at all) is a different enough shape that reusing it would mean
threading a shape-selector through code that has none today. `clawseccheck/sbom_runs.py`
reuses monitorstore.py's generic hash-chain primitives instead, the same way
runstore.py itself does — proven generic across three independent stores now.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.collector import Context
from clawseccheck.sbom import (
    build_sbom,
    render_sbom_cyclonedx,
    render_sbom_spdx,
)
from clawseccheck.sbom_runs import (
    diff_sbom_runs,
    list_sbom_run_ids,
    load_sbom_run,
    render_sbom_diff_json,
    save_sbom_run,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")
_HOME_FAKE = Path("/nonexistent/home")


def _ctx_with_everything() -> Context:
    """One skill, one MCP server, one plugin — enough to exercise every branch of
    every renderer at once, mirroring tests/test_sbom.py's own fixture-construction
    idiom (direct Context field assignment, no live audit)."""
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {
        "net-fetcher": "---\nname: x\ndescription: y\nversion: 1.2.0\n---\nrequests>=2.0\n",
    }
    ctx.config = {
        "mcp": {"servers": {"svc": {
            "command": "npx", "args": ["svc-mcp@1.2.3"], "transport": "stdio",
            "env": {"API_KEY": "secret-value"},
        }}},
    }
    ctx.plugin_index_found = True
    ctx.plugin_index_records = [{
        "plugin_id": "alpha", "origin": "config", "enabled": True,
        "root_dir": None, "manifest_path": None, "source": None,
        "contracts": {"tools": ["x"]},
    }]
    return ctx


def _ctx_no_version_skill() -> Context:
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {"no-ver": "---\nname: x\ndescription: y\n---\n"}
    ctx.config = {}
    ctx.plugin_index_found = True
    ctx.plugin_index_records = []
    return ctx


# ------------------------------------------------------------------ minimal offline schema

# A hand-authored, MINIMAL structural check — not the real CycloneDX/SPDX JSON Schema
# (no network fetch, ever; Golden Rule #1) — just enough to catch a renderer that drifts
# from valid key names/nesting/types for the handful of fields this module asserts.

def _assert_cyclonedx_shape(doc: dict) -> None:
    assert doc["bomFormat"] == "CycloneDX"
    assert isinstance(doc["specVersion"], str)
    assert isinstance(doc["version"], int)
    assert isinstance(doc["components"], list)
    for c in doc["components"]:
        assert isinstance(c["type"], str)
        assert isinstance(c["name"], str) and c["name"]
        assert isinstance(c["bom-ref"], str)
        assert isinstance(c["hashes"], list) and c["hashes"]
        for h in c["hashes"]:
            assert h["alg"] == "SHA-256"
            assert isinstance(h["content"], str)
            assert len(h["content"]) == 64
            int(h["content"], 16)  # must be valid hex
        if "version" in c:
            assert isinstance(c["version"], str)
        assert "licenses" not in c  # never fabricated
        assert "purl" not in c  # never fabricated


def _assert_spdx_shape(doc: dict) -> None:
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert isinstance(doc["documentNamespace"], str)
    assert isinstance(doc["creationInfo"]["created"], str)
    assert isinstance(doc["creationInfo"]["creators"], list) and doc["creationInfo"]["creators"]
    assert isinstance(doc["packages"], list)
    for p in doc["packages"]:
        assert isinstance(p["SPDXID"], str) and p["SPDXID"].startswith("SPDXRef-")
        assert isinstance(p["name"], str) and p["name"]
        assert isinstance(p["versionInfo"], str)
        assert p["downloadLocation"] == "NOASSERTION"
        assert p["filesAnalyzed"] is False
        assert p["licenseConcluded"] == "NOASSERTION"
        assert p["licenseDeclared"] == "NOASSERTION"
        assert isinstance(p["checksums"], list) and p["checksums"]
        for c in p["checksums"]:
            assert c["algorithm"] == "SHA256"
            assert len(c["checksumValue"]) == 64
            int(c["checksumValue"], 16)


# --------------------------------------------------------------------------- CycloneDX


def test_cyclonedx_shape_is_structurally_valid_with_all_three_kinds():
    doc = json.loads(render_sbom_cyclonedx(_ctx_with_everything()))
    _assert_cyclonedx_shape(doc)
    assert len(doc["components"]) == 3
    assert {c["name"] for c in doc["components"]} == {"net-fetcher", "svc", "alpha"}


def test_cyclonedx_hash_is_the_full_untruncated_form_of_the_native_hash():
    """Same input bytes as the native format's own _h(), just not truncated to 16 chars
    — reuse the digest machinery, never a second hashing convention."""
    ctx = _ctx_with_everything()
    native = build_sbom(ctx)
    cdx = json.loads(render_sbom_cyclonedx(ctx))
    native_hash = native["skills"][0]["hash"]
    cdx_hash = next(c for c in cdx["components"] if c["name"] == "net-fetcher")["hashes"][0]["content"]
    assert cdx_hash.startswith(native_hash)  # 16-char prefix of the same full digest
    assert len(native_hash) == 16
    assert len(cdx_hash) == 64


def test_cyclonedx_omits_version_when_unknown_rather_than_fabricating():
    doc = json.loads(render_sbom_cyclonedx(_ctx_no_version_skill()))
    comp = doc["components"][0]
    assert "version" not in comp


def test_cyclonedx_never_asserts_a_license():
    doc = json.loads(render_sbom_cyclonedx(_ctx_with_everything()))
    assert all("licenses" not in c for c in doc["components"])


def test_cyclonedx_is_deterministic_no_wall_clock_field():
    ctx = _ctx_with_everything()
    a = render_sbom_cyclonedx(ctx)
    b = render_sbom_cyclonedx(ctx)
    assert a == b
    assert "timestamp" not in a


def test_cyclonedx_carries_declared_and_unpinned_deps_as_properties():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {
        "x": "---\nname: x\ndescription: y\n---\n# file: requirements.txt\nrequests\nflask==3.0.2\n",
    }
    ctx.config = {}
    ctx.plugin_index_found = True
    ctx.plugin_index_records = []
    doc = json.loads(render_sbom_cyclonedx(ctx))
    props = {p["name"]: p["value"] for p in doc["components"][0].get("properties", [])}
    assert "clawseccheck:declaredDeps" in props or "clawseccheck:unpinnedDeps" in props


# --------------------------------------------------------------------------- SPDX


def test_spdx_shape_is_structurally_valid_with_all_three_kinds():
    doc = json.loads(render_sbom_spdx(_ctx_with_everything()))
    _assert_spdx_shape(doc)
    assert len(doc["packages"]) == 3


def test_spdx_hash_is_the_full_untruncated_form_of_the_native_hash():
    ctx = _ctx_with_everything()
    native = build_sbom(ctx)
    spdx = json.loads(render_sbom_spdx(ctx))
    native_hash = native["skills"][0]["hash"]
    pkg = next(p for p in spdx["packages"] if p["name"] == "net-fetcher")
    assert pkg["checksums"][0]["checksumValue"].startswith(native_hash)


def test_spdx_uses_noassertion_for_unknown_version_and_license():
    doc = json.loads(render_sbom_spdx(_ctx_no_version_skill()))
    pkg = doc["packages"][0]
    assert pkg["versionInfo"] == "NOASSERTION"
    assert pkg["licenseConcluded"] == "NOASSERTION"
    assert pkg["licenseDeclared"] == "NOASSERTION"


def test_spdx_records_the_known_version_when_present():
    doc = json.loads(render_sbom_spdx(_ctx_with_everything()))
    pkg = next(p for p in doc["packages"] if p["name"] == "net-fetcher")
    assert pkg["versionInfo"] == "1.2.0"


def test_spdx_ids_stay_unique_when_two_names_sanitize_to_the_same_string():
    """C-135: "a/b" and "a b" both fold to "a-b" once non-alnum/./- characters are
    replaced — SPDXID must be unique per document, and a naive sanitize-only id
    silently collided the two into one, which a strict SPDX consumer could reject
    outright or resolve to only one of the two real components."""
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {
        "a/b": "---\nname: x\ndescription: y\n---\n",
        "a b": "---\nname: y\ndescription: y\n---\n",
    }
    ctx.config = {}
    ctx.plugin_index_found = True
    ctx.plugin_index_records = []
    doc = json.loads(render_sbom_spdx(ctx))
    ids = [p["SPDXID"] for p in doc["packages"]]
    assert len(ids) == len(set(ids)), f"SPDXID collision: {ids}"


def test_spdx_component_inventory_matches_native_despite_the_timestamp_field():
    """SPDX's own creationInfo.created is real wall-clock time by convention (unlike
    the native/CycloneDX formats, which stay fully deterministic) — but the component
    LIST itself must still be identical across two renders of an unchanged Context."""
    ctx = _ctx_with_everything()
    a = json.loads(render_sbom_spdx(ctx))
    b = json.loads(render_sbom_spdx(ctx))
    names_a = sorted((p["name"], p["checksums"][0]["checksumValue"]) for p in a["packages"])
    names_b = sorted((p["name"], p["checksums"][0]["checksumValue"]) for p in b["packages"])
    assert names_a == names_b


# --------------------------------------------------------------------------- CLI: --format


def test_cli_sbom_default_format_is_unchanged_native(capsys):
    rc = main(["--sbom", "--home", SAFE])
    out = capsys.readouterr().out
    assert rc == 0
    doc = json.loads(out)
    assert "bomFormat" not in doc and "spdxVersion" not in doc
    assert doc["version"] == 3  # SBOM_VERSION, unaffected by this task


def test_cli_sbom_format_cyclonedx(capsys):
    rc = main(["--sbom", "--format", "cyclonedx", "--home", SAFE])
    out = capsys.readouterr().out
    assert rc == 0
    _assert_cyclonedx_shape(json.loads(out))


def test_cli_sbom_format_spdx(capsys):
    rc = main(["--sbom", "--format", "spdx", "--home", SAFE])
    out = capsys.readouterr().out
    assert rc == 0
    _assert_spdx_shape(json.loads(out))


def test_format_has_no_effect_without_sbom(capsys):
    main(["--vet-plan", "foo", "--format", "cyclonedx", "--home", SAFE])
    err = capsys.readouterr().err
    assert "--format has no effect with --vet-plan" in err


def test_format_native_gives_no_no_effect_note_even_without_sbom(capsys):
    """--format defaults to "native" — the default value must never itself trigger a
    disclosure, or every run of every other mode would print a spurious note."""
    main(["--vet-plan", "foo", "--home", SAFE])
    err = capsys.readouterr().err
    assert "--format" not in err


# --------------------------------------------------------------------------- sbom_runs.py


def test_save_sbom_run_round_trips_through_load(tmp_path):
    p = tmp_path / "sbom_runs.jsonl"
    sbom = {"skills": [{"name": "a", "version": "1.0", "hash": "h1"}],
           "mcp_servers": [], "plugins": []}
    rid = save_sbom_run(sbom, str(p), version="4.0.1")
    assert rid is not None
    row = load_sbom_run(rid, str(p))
    assert row is not None
    assert row["ts"] == rid
    assert row["sbom"] == sbom


def test_list_sbom_run_ids_empty_when_absent(tmp_path):
    assert list_sbom_run_ids(str(tmp_path / "nope.jsonl")) == []


def test_list_sbom_run_ids_lists_every_saved_run(tmp_path):
    p = tmp_path / "sbom_runs.jsonl"
    save_sbom_run({"skills": [], "mcp_servers": [], "plugins": []}, str(p),
                  when="2026-01-01T00:00:00")
    save_sbom_run({"skills": [], "mcp_servers": [], "plugins": []}, str(p),
                  when="2026-01-02T00:00:00")
    assert list_sbom_run_ids(str(p)) == ["2026-01-01T00:00:00", "2026-01-02T00:00:00"]


def test_diff_identifies_added_removed_and_changed():
    run1 = {"ts": "t1", "sbom": {
        "skills": [{"name": "a", "version": "1.0", "hash": "h1"},
                  {"name": "gone", "version": "1.0", "hash": "hg"}],
        "mcp_servers": [], "plugins": [],
    }}
    run2 = {"ts": "t2", "sbom": {
        "skills": [{"name": "a", "version": "1.1", "hash": "h2"},
                  {"name": "new", "version": "1.0", "hash": "hn"}],
        "mcp_servers": [], "plugins": [],
    }}
    diff = diff_sbom_runs(run1, run2)
    assert [c["name"] for c in diff["added"]] == ["new"]
    assert [c["name"] for c in diff["removed"]] == ["gone"]
    assert len(diff["changed"]) == 1
    assert diff["changed"][0]["name"] == "a"
    assert diff["changed"][0]["changed"]["version"] == {"from": "1.0", "to": "1.1"}
    assert diff["changed"][0]["changed"]["hash"] == {"from": "h1", "to": "h2"}


def test_diff_a_hash_change_alone_is_still_reported_as_changed():
    """The exact supply-chain-swap signal this feature exists to catch: SAME declared
    version, DIFFERENT content hash."""
    run1 = {"ts": "t1", "sbom": {"skills": [{"name": "a", "version": "1.0", "hash": "h1"}],
                                 "mcp_servers": [], "plugins": []}}
    run2 = {"ts": "t2", "sbom": {"skills": [{"name": "a", "version": "1.0", "hash": "h2"}],
                                 "mcp_servers": [], "plugins": []}}
    diff = diff_sbom_runs(run1, run2)
    assert diff["changed"][0]["changed"] == {"hash": {"from": "h1", "to": "h2"}}
    assert "version" not in diff["changed"][0]["changed"]


def test_diff_identical_runs_is_empty():
    sbom = {"skills": [{"name": "a", "version": "1.0", "hash": "h1"}],
           "mcp_servers": [], "plugins": []}
    run1 = {"ts": "t1", "sbom": sbom}
    run2 = {"ts": "t2", "sbom": sbom}
    diff = diff_sbom_runs(run1, run2)
    assert diff["added"] == []
    assert diff["removed"] == []
    assert diff["changed"] == []
    assert diff["unchanged_count"] == 1


def test_two_nameless_entries_are_never_collapsed_into_one_false_change():
    """C-135: build_sbom() always sets "name" — this is about a malformed/legacy-
    schema stored row. Two DIFFERENT nameless entries used to both key on (kind, ""),
    so a genuine remove-one+add-one pair silently read as one component's version and
    hash "changing" — asserting a supply-chain-swap-shaped claim about a component
    identity that was never real. Must report as one add + one remove instead."""
    run1 = {"ts": "t1", "sbom": {"skills": [{"version": "1.0", "hash": "h1"}],
                                 "mcp_servers": [], "plugins": []}}
    run2 = {"ts": "t2", "sbom": {"skills": [{"version": "2.0", "hash": "h2"}],
                                 "mcp_servers": [], "plugins": []}}
    diff = diff_sbom_runs(run1, run2)
    assert diff["changed"] == []
    assert len(diff["added"]) == 1 and diff["added"][0]["hash"] == "h2"
    assert len(diff["removed"]) == 1 and diff["removed"][0]["hash"] == "h1"


def test_changed_entries_report_the_real_name_never_the_internal_fallback_marker():
    """A "changed" entry's "name" must come from the entry's own field, not the
    identity tuple used to MATCH the two entries — which can be the synthetic
    "<unnamed:...>" marker for a nameless component and must never leak out as if it
    were real component data."""
    run1 = {"ts": "t1", "sbom": {"skills": [{"name": "a", "version": "1.0", "hash": "h1"}],
                                 "mcp_servers": [], "plugins": []}}
    run2 = {"ts": "t2", "sbom": {"skills": [{"name": "a", "version": "1.1", "hash": "h1"}],
                                 "mcp_servers": [], "plugins": []}}
    diff = diff_sbom_runs(run1, run2)
    assert diff["changed"][0]["name"] == "a"
    assert "<unnamed" not in diff["changed"][0]["name"]


def test_render_sbom_diff_json_shape():
    run1 = {"ts": "t1", "sbom": {"skills": [], "mcp_servers": [], "plugins": []}}
    run2 = {"ts": "t2", "sbom": {"skills": [{"name": "a", "version": None, "hash": "h"}],
                                 "mcp_servers": [], "plugins": []}}
    diff = diff_sbom_runs(run1, run2)
    payload = json.loads(render_sbom_diff_json(diff, version="4.0.1"))
    assert payload["tool"] == "clawseccheck"
    assert payload["run1"] == "t1"
    assert payload["run2"] == "t2"
    assert len(payload["added"]) == 1
    assert payload["unchangedCount"] == 0


# --------------------------------------------------------------------------- CLI: --sbom-diff


def _save_two_sbom_runs(store: str) -> "tuple[str, str]":
    p = str(Path(store) / "sbom_runs.jsonl")
    sbom1 = {"skills": [{"name": "a", "version": "1.0", "hash": "h1"}],
            "mcp_servers": [], "plugins": []}
    sbom2 = {"skills": [{"name": "a", "version": "1.1", "hash": "h2"},
                       {"name": "b", "version": None, "hash": "h3"}],
            "mcp_servers": [], "plugins": []}
    id1 = save_sbom_run(sbom1, p, when="2026-01-01T00:00:00")
    id2 = save_sbom_run(sbom2, p, when="2026-01-02T00:00:00")
    return id1, id2


def test_cli_save_sbom_run_creates_store_and_prints_id(tmp_path, capsys):
    rc = main(["--sbom", "--save-sbom-run", "--home", SAFE, "--data-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert (tmp_path / "sbom_runs.jsonl").is_file()
    assert "SBOM run saved as" in out
    assert "--sbom-diff" in out


def test_cli_default_sbom_run_never_creates_the_store(tmp_path, capsys):
    main(["--sbom", "--home", SAFE, "--data-dir", str(tmp_path)])
    capsys.readouterr()
    assert not (tmp_path / "sbom_runs.jsonl").exists()


def test_cli_sbom_diff_text(tmp_path, capsys):
    id1, id2 = _save_two_sbom_runs(str(tmp_path))
    capsys.readouterr()
    rc = main(["--sbom-diff", id1, id2, "--data-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 added component(s)" in out
    assert "1 changed component(s)" in out
    assert "No removed components." in out


def test_cli_sbom_diff_json(tmp_path, capsys):
    id1, id2 = _save_two_sbom_runs(str(tmp_path))
    capsys.readouterr()
    rc = main(["--sbom-diff", id1, id2, "--json", "--data-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload["run1"] == id1
    assert payload["run2"] == id2


def test_cli_sbom_diff_missing_run(tmp_path, capsys):
    rc = main(["--sbom-diff", "nope1", "nope2", "--data-dir", str(tmp_path)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "no saved SBOM run found" in err


def test_cli_sbom_diff_blank_run_id(tmp_path, capsys):
    rc = main(["--sbom-diff", "", "nope2", "--data-dir", str(tmp_path)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "cannot be blank" in err


def test_cli_sbom_diff_with_no_store_at_all(tmp_path, capsys):
    rc = main(["--sbom-diff", "a", "b", "--data-dir", str(tmp_path)])
    assert rc == 1


def test_cli_sbom_diff_is_read_only(tmp_path, capsys):
    id1, id2 = _save_two_sbom_runs(str(tmp_path))
    before = {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in tmp_path.iterdir()}
    capsys.readouterr()
    main(["--sbom-diff", id1, id2, "--data-dir", str(tmp_path)])
    after = {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in tmp_path.iterdir()}
    assert before == after


def test_cli_purge_removes_sbom_runs_store(tmp_path, capsys):
    main(["--sbom", "--save-sbom-run", "--home", SAFE, "--data-dir", str(tmp_path)])
    capsys.readouterr()
    assert (tmp_path / "sbom_runs.jsonl").is_file()
    main(["--purge", "--yes", "--data-dir", str(tmp_path)])
    capsys.readouterr()
    assert not (tmp_path / "sbom_runs.jsonl").exists()


def test_save_sbom_run_stores_the_native_shape_regardless_of_format(tmp_path, capsys):
    """--format only selects OUTPUT rendering; --save-sbom-run always persists the
    native build_sbom(ctx) shape so --sbom-diff compares components, never text that
    also varies with e.g. SPDX's own wall-clock creationInfo.created."""
    rc = main(["--sbom", "--format", "spdx", "--save-sbom-run", "--home", SAFE,
              "--data-dir", str(tmp_path)])
    capsys.readouterr()
    assert rc == 0
    ids = list_sbom_run_ids(str(tmp_path / "sbom_runs.jsonl"))
    assert len(ids) == 1
    row = load_sbom_run(ids[0], str(tmp_path / "sbom_runs.jsonl"))
    assert "spdxVersion" not in row["sbom"]
    assert "skills" in row["sbom"]  # the native shape's own top-level key
