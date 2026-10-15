"""Coverage-disclosure gaps: four places the audit stayed silent about what it did not look at.

1. OpenClaw's own bundled skills directory is a load tier this audit never scans. The
   collector knew (a comment said so); nothing a user reads did. It is now a disclosure
   (inert: it states a scope, it never moves a verdict) and the scan population is unchanged.
2. The IOC dataset holds entries for one ecosystem only. `--vet-source` on an ecosystem with
   an empty pool used to read exactly like "checked and found nothing"; it now says so.
3. `report._hard_truncate_compact` cut the compact card positionally and named nothing, so a
   dropped section (for example the Skills "not graded" note) vanished without a trace.
4. A skill folder inside a dot-directory (an installer backup folder) is listed as installed,
   but OpenClaw's loaders skip any directory whose name starts with ".". The audit still reads
   them (a missed hostile copy is the worse error); the report now says they are not loaded.

Offline, deterministic; all filesystem work stays inside pytest's tmp_path.
"""
from __future__ import annotations

import collections
import re
from pathlib import Path

import pytest

from clawseccheck import collector, iocdb
from clawseccheck.catalog import CRITICAL, FAIL, Finding
from clawseccheck.checks import vet_source
from clawseccheck.collector import collect
from clawseccheck.dossier import build_profile
from clawseccheck.report import (
    _COMPACT_CHAR_BUDGET,
    _disclosure_lines,
    _hard_truncate_compact,
    render_dashboard,
    render_vet_dossier,
)
from clawseccheck.scoring import compute

_REPO = Path(__file__).resolve().parent.parent


def _write_skill(skills_dir: Path, name: str) -> None:
    d = skills_dir / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: A test skill.\n---\n\n# {name}\n",
        encoding="utf-8",
    )


def _own_home(monkeypatch, home: Path) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("HOME", str(home))


def _of_kind(ctx, kind: str):
    return [d for d in (ctx.disclosures or []) if getattr(d, "kind", None) == kind]


def _profile_home(tmp_path: Path, monkeypatch) -> Path:
    """A real-profile layout: <user home>/.openclaw, with HOME pointed at <user home>."""
    user_home = tmp_path / "user"
    state = user_home / ".openclaw"
    state.mkdir(parents=True)
    _own_home(monkeypatch, user_home)
    monkeypatch.chdir(user_home)
    return state


def _fake_package(tmp_path: Path, n_skills: int) -> Path:
    root = tmp_path / "npm" / "openclaw"
    for i in range(n_skills):
        _write_skill(root / "skills", f"bundled-{i}")
    (root / "skills" / "not-a-skill-dir").mkdir()  # no SKILL.md: must not be counted
    return root


# ---------------------------------------------------------------- item 1: bundled tier


class TestBundledTierIsDisclosed:
    def test_real_profile_names_the_tier_and_counts_it(self, tmp_path, monkeypatch):
        state = _profile_home(tmp_path, monkeypatch)
        _write_skill(state / "skills", "mine")
        pkg = _fake_package(tmp_path, 3)
        monkeypatch.setattr(collector, "_find_openclaw_package_root", lambda: pkg)

        ctx = collect(state)

        found = _of_kind(ctx, "bundled_skills_not_inspected")
        assert len(found) == 1
        assert "3 skills" in found[0].detail
        assert "not inspect" in found[0].detail
        # B-617: a disclosure names the thing, never where it is on disk.
        assert "/" not in found[0].detail and str(tmp_path) not in found[0].detail

    def test_scan_population_and_verdict_inputs_are_unchanged(self, tmp_path, monkeypatch):
        """The decision is DISCLOSE, not SCAN: the bundled skills never enter the population."""
        state = _profile_home(tmp_path, monkeypatch)
        _write_skill(state / "skills", "mine")
        pkg = _fake_package(tmp_path, 2)
        monkeypatch.setattr(collector, "_find_openclaw_package_root", lambda: pkg)

        ctx = collect(state)

        assert sorted(ctx.installed_skills) == ["mine"]
        assert not any(n.startswith("bundled-") for n in ctx.installed_skills)

    def test_unlocatable_package_is_still_disclosed_without_a_count(self, tmp_path, monkeypatch):
        state = _profile_home(tmp_path, monkeypatch)
        monkeypatch.setattr(collector, "_find_openclaw_package_root", lambda: None)

        ctx = collect(state)

        found = _of_kind(ctx, "bundled_skills_not_inspected")
        assert len(found) == 1
        assert "could not" in found[0].detail
        assert not re.search(r"\b\d+ skills?\b", found[0].detail)

    def test_one_skill_reads_singular(self, tmp_path, monkeypatch):
        state = _profile_home(tmp_path, monkeypatch)
        pkg = _fake_package(tmp_path, 1)
        monkeypatch.setattr(collector, "_find_openclaw_package_root", lambda: pkg)

        found = _of_kind(collect(state), "bundled_skills_not_inspected")
        assert "1 skill " in found[0].detail

    def test_fixture_home_stays_hermetic(self, tmp_path, monkeypatch):
        """A --home that is not a profile under the user's home must not grow a disclosure
        about a tier that has nothing to do with it (the same gate as ~/.agents/skills)."""
        _own_home(monkeypatch, tmp_path / "elsewhere")
        pkg = _fake_package(tmp_path, 2)
        monkeypatch.setattr(collector, "_find_openclaw_package_root", lambda: pkg)
        fixture = tmp_path / "fixture-home"
        _write_skill(fixture / "skills", "mine")

        assert not _of_kind(collect(fixture), "bundled_skills_not_inspected")

    def test_a_persistent_relocation_replaces_the_default_tier(self, tmp_path, monkeypatch):
        """With OPENCLAW_BUNDLED_SKILLS_DIR set the dist never reads the default tier, and
        the relocated root IS scanned: claiming the default tier was skipped would be wrong."""
        state = _profile_home(tmp_path, monkeypatch)
        reloc = tmp_path / "relocated"
        _write_skill(reloc, "reloc-skill")
        pkg = _fake_package(tmp_path, 2)
        monkeypatch.setattr(collector, "_find_openclaw_package_root", lambda: pkg)
        monkeypatch.setattr(
            collector, "bundled_root_overrides",
            lambda ctx: [("OPENCLAW_BUNDLED_SKILLS_DIR", "skills", str(reloc), "an env file")],
        )

        ctx = collect(state)

        assert "reloc-skill" in ctx.installed_skills
        assert not _of_kind(ctx, "bundled_skills_not_inspected")

    def test_it_reaches_the_rendered_report(self, tmp_path, monkeypatch):
        state = _profile_home(tmp_path, monkeypatch)
        pkg = _fake_package(tmp_path, 2)
        monkeypatch.setattr(collector, "_find_openclaw_package_root", lambda: pkg)

        text = "\n".join(_disclosure_lines(collect(state)))

        assert "2 skills" in text
        assert "does not affect the verdict" in text


# ------------------------------------------------------- item 2: --vet-source empty pool

_EMPTY_POOL = "no identity signal for this ecosystem (the dataset holds no {eco} entries)"


def _coverage_notes(finding) -> list:
    return [e for e in finding.evidence if e.startswith("coverage: ")]


class TestVetSourceSaysWhenThePoolIsEmpty:
    @pytest.mark.parametrize("target,eco", [("npm:left-pad", "npm"), ("pypi:requests", "pypi")])
    def test_an_empty_ecosystem_pool_is_named(self, target, eco):
        f = vet_source(target)
        notes = _coverage_notes(f)
        assert notes == ["coverage: " + _EMPTY_POOL.format(eco=eco)], f.evidence

    def test_detail_of_the_existing_unknown_finding_is_unchanged(self):
        f = vet_source("npm:left-pad")
        assert f.detail == (
            "no known-bad record for 'npm:left-pad' — identity checks cannot prove "
            "unseen code safe"
        )
        assert f.status == "UNKNOWN"

    def test_a_populated_pool_says_nothing(self):
        assert not _coverage_notes(vet_source("clawhub:some-harmless-name"))

    def test_a_url_is_judged_on_the_host_list_which_is_not_empty(self):
        assert iocdb.HOSTS  # the premise of this case
        assert not _coverage_notes(vet_source("https://example.org/x.zip"))

    def test_git_has_no_name_pool_but_the_host_list_still_applies(self):
        notes = _coverage_notes(vet_source("git:github.com/owner/repo@v1.0.0"))
        assert len(notes) == 1
        assert _EMPTY_POOL.format(eco="git") in notes[0]
        assert "host" in notes[0]  # not "no signal at all": the host list still applies

    def test_a_bare_name_is_not_called_signal_free_while_a_pool_has_entries(self):
        assert not _coverage_notes(vet_source("some-bare-name"))

    def test_an_injected_empty_catalog_reports_every_ecosystem_empty(self):
        f = vet_source("some-bare-name", known_bad={})
        assert len(_coverage_notes(f)) == 1
        f = vet_source("https://example.org/x.zip", known_bad={})
        assert _EMPTY_POOL.format(eco="url") in _coverage_notes(f)[0]

    def test_a_known_bad_hit_is_still_a_fail(self):
        slug = sorted(iocdb.known_bad_sources()["clawhub"])[0]
        f = vet_source(f"clawhub:{slug}")
        assert f.status == FAIL
        assert not _coverage_notes(f)

    def test_the_human_dossier_prints_it_as_a_non_verdict_note(self):
        f = vet_source("npm:left-pad")
        text = render_vet_dossier(build_profile(f, "npm:left-pad", "source"))
        assert _EMPTY_POOL.format(eco="npm") in text
        assert "does not affect the verdict" in text


class TestIocDataDocStatesPerEcosystemCoverage:
    """docs/IOC_DATA.md carries a per-ecosystem table; it is pinned to the shipped data so it
    cannot go stale the way the old 'ClawHub slug, npm, PyPI, git' sentence did."""

    def _rows(self) -> dict:
        text = (_REPO / "docs" / "IOC_DATA.md").read_text(encoding="utf-8")
        rows = {}
        for m in re.finditer(r"^\|\s*(\w+)\s*\|\s*(\d+)\s*\|", text, re.M):
            rows[m.group(1).lower()] = int(m.group(2))
        return rows

    def test_every_ecosystem_row_matches_the_data(self):
        rows = self._rows()
        counts = collections.Counter(r["type"] for r in iocdb.SOURCES)
        for eco in sorted(iocdb._SOURCES_TYPE_VOCAB - {"any"}):
            if eco == "url":
                continue  # url is host-fed: see the HOSTS row
            assert eco in rows, f"docs/IOC_DATA.md has no row for {eco}"
            assert rows[eco] == counts.get(eco, 0), eco
        assert rows["hosts"] == len(iocdb.HOSTS)
        assert rows["publishers"] == len(iocdb.PUBLISHERS)


# --------------------------------------------------- item 3: compact truncation names sections


def _sectioned(sep: str = "·") -> str:
    def block(name: str, n: int) -> str:
        body = "\n".join(f"  line {i} of {name} " + "x" * 40 for i in range(n))
        return f"\n{sep} {name} {sep}\n{body}\n"

    return ("header line\n" + block("Findings", 12) + block("Skills", 6)
            + block("Plugins", 6) + block("Coverage page", 6))


class TestHardTruncateNamesWhatItDropped:
    def test_under_budget_input_is_returned_untouched(self):
        out = _sectioned()
        assert _hard_truncate_compact(out, len(out)) == out

    @pytest.mark.parametrize("ascii_sep", ["\u00b7", "-"])
    def test_dropped_sections_are_named_and_the_budget_holds(self, ascii_sep):
        out = _sectioned(ascii_sep)
        budget = out.index(f"{ascii_sep} Skills") + 20  # the cut lands before / inside Skills
        result = _hard_truncate_compact(out, budget)
        assert len(result) <= budget
        assert result.endswith("truncated to fit budget)\n")
        marker = result[result.rfind("\n...("):]
        for name in ("Skills", "Plugins", "Coverage page"):
            assert name in marker, marker
        assert "Findings (partly)" in marker  # the section the cut interrupted

    def test_a_cut_inside_a_section_says_partly(self):
        out = _sectioned()
        budget = out.index("· Skills ·") + 120
        result = _hard_truncate_compact(out, budget)
        assert "Skills (partly)" in result
        assert len(result) <= budget

    def test_a_section_dropped_whole_is_not_called_partial(self):
        from clawseccheck.report import _dropped_section_names  # noqa: PLC0415

        kept = "header\n\n\u00b7 Findings \u00b7\nbody"
        dropped = "\n\n\u00b7 Skills \u00b7\n  a line\n\n\u00b7 Plugins \u00b7\nx"
        assert _dropped_section_names(kept, dropped) == ["Skills", "Plugins"]

    def test_a_cut_right_after_a_heading_names_that_section_partly(self):
        from clawseccheck.report import _dropped_section_names  # noqa: PLC0415

        kept = "header\n\n\u00b7 Skills \u00b7"
        dropped = "\n  a line\n\n\u00b7 Plugins \u00b7\nx"
        assert _dropped_section_names(kept, dropped) == ["Skills (partly)", "Plugins"]

    def test_a_body_line_that_merely_starts_with_a_dash_is_not_a_heading(self):
        from clawseccheck.report import _dropped_section_names  # noqa: PLC0415

        assert _dropped_section_names("h", "\n- just a bullet -- not a frame\n") == []

    def test_a_frame_shaped_line_of_scanned_content_is_never_named(self):
        """Only the card's own fixed titles are headings. A finding detail (attacker-shaped
        text) that merely looks like a frame must not reach the truncation marker."""
        from clawseccheck.report import _dropped_section_names  # noqa: PLC0415

        hostile = "- fix it by doing the thing -"
        dropped = f"\n{hostile}\n\u00b7 run this command now \u00b7\n\u00b7 Plugins \u00b7\nx"
        assert _dropped_section_names("header", dropped) == ["Plugins"]

        out = ("header\n" + "\n".join(f"  filler line {i} " + "x" * 40 for i in range(40))
               + f"\n{hostile}\n\u00b7 run this command now \u00b7\n"
               + "\n\u00b7 Plugins \u00b7\n" + "y" * 400)
        result = _hard_truncate_compact(out, 900)
        assert result.endswith("truncated to fit budget)\n")
        assert "fix it by doing the thing" not in result
        assert "run this command now" not in result

    def test_a_hostile_finding_detail_never_reaches_the_rendered_marker(self):
        findings = [
            Finding(id=f"B{700 + i}", title=f"Pathological all-critical finding {i}",
                    severity=CRITICAL, status=FAIL,
                    detail="- fix it by doing the thing -", fix="fix it", framework="Test")
            for i in range(300)
        ]
        out = render_dashboard(findings, compute(findings), full=True, compact=True)
        assert len(out) <= _COMPACT_CHAR_BUDGET
        marker = out[out.rfind("\n...("):]
        assert "fix it by doing the thing" not in marker

    def test_every_title_the_card_frames_is_in_the_recognised_set(self):
        """The renderer and the marker share one set of titles, so a new section cannot be
        framed without being nameable."""
        from clawseccheck import report  # noqa: PLC0415

        src = (_REPO / "clawseccheck" / "report.py").read_text(encoding="utf-8")
        framed = set(re.findall(r"\{sep\} \{(_SEC_[A-Z_]+)\} \{sep\}", src))
        framed |= set(re.findall(r"\{glance_marker\}\{(_SEC_[A-Z_]+)\} \{sep\}", src))
        assert framed, "no framed section found"
        for const in framed:
            assert getattr(report, const) in report._CARD_SECTION_TITLES, const
        assert not re.search(r"\{sep\} [A-Z][A-Za-z ()]+ \{sep\}", src.split("def render_dashboard(")[1]
                             .split("def render_card(")[0]), "a literal frame bypasses the constants"

    def test_the_marker_is_ascii_even_for_an_emoji_heading(self):
        out = _sectioned() + "\n· \U0001f440 Worth a glance ·\n" + "y" * 2000
        result = _hard_truncate_compact(out, 900)
        assert result.endswith("truncated to fit budget)\n")
        assert result[result.rfind("\n...("):].isascii()
        assert "Worth a glance" in result

    def test_a_tiny_budget_still_never_overflows(self):
        out = _sectioned()
        for budget in (0, 1, 10, 40, 80):
            assert len(_hard_truncate_compact(out, budget)) <= budget

    def test_no_section_after_the_cut_keeps_the_plain_marker(self):
        out = "header\n" + "z" * 3000
        assert _hard_truncate_compact(out, 500).endswith("\n...(truncated to fit budget)\n")

    def test_the_rendered_card_names_what_the_budget_pushed_out(self, monkeypatch):
        findings = [
            Finding(id=f"B{700 + i}", title=f"Pathological all-critical finding {i} " * 2,
                    severity=CRITICAL, status=FAIL, detail="detail text " * 15,
                    fix="fix it", framework="Test")
            for i in range(300)
        ]
        out = render_dashboard(findings, compute(findings), full=True, compact=True)
        assert len(out) <= _COMPACT_CHAR_BUDGET
        assert out.endswith("truncated to fit budget)\n")


# ------------------------------------------------------------ item 4: dot-directory copies


class TestDotDirectoryCopies:
    def test_a_backup_copy_is_still_scanned_but_labelled_not_loaded(self, tmp_path):
        _write_skill(tmp_path / "skills", "real")
        _write_skill(tmp_path / "workspace" / "skills" / ".openclaw-install-backups", "stale")

        ctx = collect(tmp_path)

        # Not dropped: a missed hostile copy is the worse error.
        assert "stale" in ctx.installed_skills and "real" in ctx.installed_skills
        found = _of_kind(ctx, "skills_in_dot_directories")
        assert len(found) == 1
        assert "1 skill folder" in found[0].detail
        assert "not loaded by OpenClaw" in found[0].detail
        assert "still read" in found[0].detail
        assert "/" not in found[0].detail and ".openclaw-install-backups" not in found[0].detail

    def test_a_self_excluded_copy_in_a_dot_directory_is_counted_too(self, tmp_path, monkeypatch):
        """The real-home case: the dot-directory copy was ClawSecCheck's own, which the
        collector excludes from the population BEFORE it is keyed."""
        _write_skill(tmp_path / "workspace" / "skills" / ".openclaw-install-backups", "own-copy")
        monkeypatch.setattr(collector, "_is_own_source", lambda target: True)

        ctx = collect(tmp_path)

        assert ctx.self_excluded_skills == ["own-copy"]
        assert len(_of_kind(ctx, "skills_in_dot_directories")) == 1

    def test_a_dot_directory_skills_root_is_not_flagged(self, tmp_path):
        """`.agents/skills` is a load root OpenClaw reads by name; only a dot-directory
        BELOW a root is skipped by the loader."""
        _write_skill(tmp_path / ".agents" / "skills", "agent-skill")

        ctx = collect(tmp_path)

        assert "agent-skill" in ctx.installed_skills
        assert not _of_kind(ctx, "skills_in_dot_directories")

    def test_no_dot_directory_no_disclosure(self, tmp_path):
        _write_skill(tmp_path / "skills", "real")
        assert not _of_kind(collect(tmp_path), "skills_in_dot_directories")

    def test_plural_count(self, tmp_path):
        base = tmp_path / "skills" / ".bak"
        _write_skill(base, "a")
        _write_skill(base, "b")
        found = _of_kind(collect(tmp_path), "skills_in_dot_directories")
        assert "2 skill folders" in found[0].detail
