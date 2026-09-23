"""B-776: sandbox-detection signal + MEDIA path fix.

A chat/dashboard session driven from INSIDE an OpenClaw sandbox has `$HOME` == the
sandbox workspace (`/workspace` on a real container) — the real `~/.openclaw` does not
exist there at all. Before this fix the audit silently scored the empty container and,
separately, a `MEDIA:<path>` directive it emitted collapsed to `~/...`, which the OpenClaw
gateway then re-expanded against the HOST's real home (not the container's), producing a
path outside the sandbox root that delivery rejects ("Path escapes sandbox root").

This file pins, offline and in-process (Path.home()/Path.cwd() monkeypatched, never a real
sandbox):

  * `collector.sandbox_sync_marker_present()` — the raw filesystem signal.
  * `collector._sandbox_signal()` / `Context.sandboxed` — the compound gate (marker AND no
    config resolvable this run), via the real `collect()`.
  * `invocation.display_path_for_delivery()` — never collapses to `~` when sandboxed;
    unchanged (`~`-collapsing) on the host path.
  * The no-config messaging (onboarding screen + the dashboard card + the terminal
    report's B-306 paragraph) states the sandbox plainly instead of generic `--home`
    advice — and leaves that advice untouched for the genuinely-fixable case (no sandbox
    signal, config just not at the default path).

Offline, deterministic; all filesystem work stays inside pytest's tmp_path.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import LOW, PASS, Finding
from clawseccheck.cli import main
from clawseccheck.collector import Context, collect, sandbox_sync_marker_present
from clawseccheck.invocation import display_path_for_delivery
from clawseccheck.menu import render_onboarding
from clawseccheck.report import render_dashboard, render_report
from clawseccheck.scoring import compute


def _write_marker(base: Path) -> None:
    skills = base / "skills"
    skills.mkdir(parents=True, exist_ok=True)
    (skills / ".openclaw-sync.json").write_text("{}", encoding="utf-8")


def _own_home(monkeypatch, home: Path) -> None:
    """Make BOTH `Path.home()` and `Path.expanduser()`/`os.path.expanduser` agree on
    *home* — the former resolves through the classmethod override, the latter (used by
    `_report_dest`'s `.expanduser()` when actually writing a file) reads `$HOME`
    directly and ignores the classmethod. A mismatch between the two is exactly the
    real bug's shape (the file lands under one home, the emitted path names another),
    so tests that write a real file need both kept in lockstep.
    """
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("HOME", str(home))


def _findings(n: int = 20) -> list:
    return [Finding("X", "t", LOW, PASS, "d", "fix", "fw", True) for _ in range(n)]


# ── Unit: the raw marker signal ────────────────────────────────────────────────

class TestMarkerSignal:
    def test_absent_by_default(self, tmp_path, monkeypatch):
        _own_home(monkeypatch, tmp_path)
        monkeypatch.chdir(tmp_path)
        assert sandbox_sync_marker_present() is False

    def test_present_under_home(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        _write_marker(home)
        _own_home(monkeypatch, home)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        assert sandbox_sync_marker_present() is True

    def test_present_under_cwd_only(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        _own_home(monkeypatch, home)
        cwd = tmp_path / "cwd"
        cwd.mkdir()
        _write_marker(cwd)
        monkeypatch.chdir(cwd)
        assert sandbox_sync_marker_present() is True

    def test_a_sibling_file_is_not_the_marker(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        (home / "skills").mkdir(parents=True)
        (home / "skills" / "openclaw-sync.json").write_text("{}")  # missing the leading dot
        _own_home(monkeypatch, home)
        monkeypatch.chdir(home)
        assert sandbox_sync_marker_present() is False

    def test_tolerates_an_unresolvable_home(self, tmp_path, monkeypatch):
        """UNKNOWN path: Path.home() itself can raise (no passwd entry / no $HOME) —
        this must degrade to False, never propagate."""
        def _raise(cls):
            raise RuntimeError("no home directory could be resolved")
        monkeypatch.setattr(Path, "home", classmethod(_raise))
        monkeypatch.chdir(tmp_path)
        assert sandbox_sync_marker_present() is False

    def test_tolerates_a_marker_dir_that_cannot_be_stat_ed(self, tmp_path, monkeypatch):
        """UNKNOWN path: skills/ exists but is unreadable — OSError on the stat, not a
        crash; falls through to the (absent) cwd check and returns False."""
        home = tmp_path / "home"
        skills = home / "skills"
        skills.mkdir(parents=True)
        (skills / ".openclaw-sync.json").write_text("{}")
        skills.chmod(0o000)
        try:
            _own_home(monkeypatch, home)
            monkeypatch.chdir(tmp_path)
            # Either False (perms blocked the stat) or True (running as root, which
            # ignores the mode) — either way it must not raise.
            sandbox_sync_marker_present()
        finally:
            skills.chmod(0o755)


# ── Unit: the compound gate via the real collect() ─────────────────────────────

class TestCollectSandboxedField:
    def test_sandboxed_when_marker_present_and_config_absent(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        _write_marker(home)
        _own_home(monkeypatch, home)
        monkeypatch.chdir(home)

        audited = tmp_path / "does-not-exist"
        ctx = collect(audited)
        assert ctx.config_found is False
        assert ctx.sandboxed is True

    def test_quiet_when_a_real_config_is_actually_found(self, tmp_path, monkeypatch):
        """A Docker-hosted gateway that legitimately HAS its own config must stay quiet
        even if the marker happens to be present."""
        home = tmp_path / "home"
        home.mkdir()
        _write_marker(home)
        _own_home(monkeypatch, home)
        monkeypatch.chdir(home)

        audited = tmp_path / "real_oc_home"
        audited.mkdir()
        cfg = audited / "openclaw.json"
        cfg.write_text("{}", encoding="utf-8")
        cfg.chmod(0o600)
        ctx = collect(audited)
        assert ctx.config_found is True
        assert ctx.sandboxed is False

    def test_quiet_when_marker_absent_even_with_no_config(self, tmp_path, monkeypatch):
        """The genuinely-fixable case: no sandbox signal, config just not there/misdirected."""
        home = tmp_path / "home"
        home.mkdir()
        _own_home(monkeypatch, home)
        monkeypatch.chdir(home)

        audited = tmp_path / "does-not-exist"
        ctx = collect(audited)
        assert ctx.config_found is False
        assert ctx.sandboxed is False


# ── Unit: display_path_for_delivery — the MEDIA-path fix itself ────────────────

class TestDisplayPathForDelivery:
    def test_host_case_collapses_to_tilde_unchanged(self, tmp_path, monkeypatch):
        _own_home(monkeypatch, tmp_path)
        target = tmp_path / ".clawseccheck" / "report.pdf"
        out = display_path_for_delivery(str(target), sandboxed=False)
        assert out.startswith("~/")
        assert "~" not in out[2:]

    def test_sandboxed_case_never_starts_with_tilde(self, tmp_path, monkeypatch):
        _own_home(monkeypatch, tmp_path)
        target = tmp_path / ".clawseccheck" / "report.pdf"
        out = display_path_for_delivery(str(target), sandboxed=True)
        assert not out.startswith("~")
        assert out == str(Path(str(target)).resolve())

    def test_sandboxed_case_points_at_a_file_this_run_created(self, tmp_path, monkeypatch):
        """The DoD: an emitted media path either points at a file this run created, or
        isn't emitted at all — never at a path the gateway will re-resolve elsewhere."""
        _own_home(monkeypatch, tmp_path)
        target = tmp_path / ".clawseccheck" / "report.pdf"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"%PDF-1.4\n")
        out = display_path_for_delivery(str(target), sandboxed=True)
        assert Path(out) == target.resolve()
        assert Path(out).is_file()


# ── Wiring: MEDIA: directive end-to-end, sandboxed vs host ─────────────────────

class TestMediaDirectiveWiring:
    def _run(self, tmp_path, monkeypatch, *, sandboxed: bool, extra=()):
        fake_home = tmp_path / "fake_home"
        fake_home.mkdir()
        if sandboxed:
            _write_marker(fake_home)
        _own_home(monkeypatch, fake_home)
        monkeypatch.chdir(fake_home)
        audited = fake_home / "oc_home"
        audited.mkdir()
        return main(["--home", str(audited), "--no-history",
                     "--data-dir", str(tmp_path / "store"), "--dashboard",
                     "--pdf", *extra])

    def test_sandboxed_media_line_never_starts_with_tilde(self, tmp_path, monkeypatch, capsys):
        self._run(tmp_path, monkeypatch, sandboxed=True)
        err = capsys.readouterr().err
        media = [ln.strip() for ln in err.splitlines() if ln.strip().startswith("MEDIA:")]
        assert media, f"no MEDIA: directive was emitted; stderr was:\n{err}"
        assert not media[0].startswith("MEDIA:~"), media

    def test_host_media_line_still_collapses_to_tilde(self, tmp_path, monkeypatch, capsys):
        """Regression: the host (non-sandboxed) path must stay byte-identical (B-381)."""
        self._run(tmp_path, monkeypatch, sandboxed=False)
        err = capsys.readouterr().err
        media = [ln.strip() for ln in err.splitlines() if ln.strip().startswith("MEDIA:")]
        assert media, f"no MEDIA: directive was emitted; stderr was:\n{err}"
        assert media[0].startswith("MEDIA:~"), media


# ── Wiring: no-config messaging — onboarding screen (bare run) ─────────────────

class TestOnboardingSandboxWording:
    def test_sandboxed_bare_run_states_sandboxed_plainly(self, tmp_path, monkeypatch, capsys):
        fake_home = tmp_path / "fake_home"
        fake_home.mkdir()
        _write_marker(fake_home)
        _own_home(monkeypatch, fake_home)
        monkeypatch.chdir(fake_home)

        rc = main(["--home", str(tmp_path / "does-not-exist"), "--no-history"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "sandboxed container" in out
        assert "--home <path>" not in out

    def test_non_sandboxed_bare_run_keeps_home_advice(self, tmp_path, monkeypatch, capsys):
        """The genuinely-fixable case: existing --home advice stays correct."""
        fake_home = tmp_path / "fake_home"
        fake_home.mkdir()
        _own_home(monkeypatch, fake_home)
        monkeypatch.chdir(fake_home)

        rc = main(["--home", str(tmp_path / "does-not-exist"), "--no-history"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "--home <path>" in out
        assert "sandboxed container" not in out

    def test_render_onboarding_sandboxed_variant_directly(self):
        out = render_onboarding(reason="missing", home="/x/.openclaw", n_checks=81,
                                sandboxed=True)
        assert "sandboxed container" in out
        assert "--home <path>" not in out
        assert "/x/.openclaw" in out

    def test_render_onboarding_non_sandboxed_variant_unchanged(self):
        out = render_onboarding(reason="missing", home="/x/.openclaw", n_checks=81,
                                sandboxed=False)
        assert "--home <path>" in out
        assert "sandboxed container" not in out


# ── Unit: no-config messaging — dashboard card + terminal report ───────────────

class TestConfigBlindMessagingWording:
    def test_render_report_states_sandboxed_plainly(self, tmp_path):
        ctx = Context(home=tmp_path)
        ctx.sandboxed = True
        findings = _findings()
        score = compute(findings, ctx)
        assert score.config_blind_reason == "absent"
        text = render_report(findings, score, ctx=ctx)
        assert "sandboxed container" in text
        assert "Point --home at the directory" not in text

    def test_render_report_keeps_home_advice_when_not_sandboxed(self, tmp_path):
        ctx = Context(home=tmp_path)  # sandboxed defaults False
        findings = _findings()
        score = compute(findings, ctx)
        assert score.config_blind_reason == "absent"
        text = render_report(findings, score, ctx=ctx)
        assert "Config visibility (CONFIG-BLIND)" in text
        assert "sandboxed container" not in text
        assert "Config visibility (CONFIG-SANDBOX)" not in text

    def test_render_dashboard_card_states_sandboxed_plainly(self, tmp_path):
        ctx = Context(home=tmp_path)
        ctx.sandboxed = True
        findings = _findings()
        score = compute(findings, ctx)
        card = render_dashboard(findings, score, ctx=ctx)
        assert "sandboxed container" in card
        assert "point --home at the directory" not in card

    def test_render_dashboard_card_keeps_home_advice_when_not_sandboxed(self, tmp_path):
        ctx = Context(home=tmp_path)
        findings = _findings()
        score = compute(findings, ctx)
        card = render_dashboard(findings, score, ctx=ctx)
        assert "point --home at the directory" in card
        assert "sandboxed container" not in card

    def test_unreadable_reason_keeps_ordinary_wording_even_if_sandboxed(self, tmp_path):
        """A present-but-corrupt config INSIDE a container is a fixable file, not a
        sandbox-visibility problem — the sandboxed sentence must not fire here."""
        ctx = Context(home=tmp_path)
        ctx.sandboxed = True
        ctx.config_found = True
        ctx.config_parse_error = True
        findings = _findings()
        score = compute(findings, ctx)
        assert score.config_blind_reason == "unreadable"
        text = render_report(findings, score, ctx=ctx)
        assert "sandboxed container" not in text
        assert "could not be read/parsed" in text
