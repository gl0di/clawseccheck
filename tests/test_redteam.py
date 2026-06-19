"""Tests for clawcheck.redteam — deterministic red-team scaffold."""
from clawcheck.redteam import (
    CATEGORIES,
    TOKEN_PREFIX,
    evaluate,
    make_suite,
    render_suite,
)
from clawcheck.cli import main


# ---------------------------------------------------------------------------
# Token format and determinism
# ---------------------------------------------------------------------------

def test_token_prefix():
    suite = make_suite()
    for entry in suite:
        assert entry["token"].startswith(TOKEN_PREFIX), (
            f"{entry['id']} token does not start with {TOKEN_PREFIX!r}"
        )


def test_token_is_ascii():
    suite = make_suite()
    for entry in suite:
        entry["token"].encode("ascii")  # raises if non-ASCII


def test_token_deterministic_same_seed():
    s1 = make_suite("my-seed")
    s2 = make_suite("my-seed")
    assert [e["token"] for e in s1] == [e["token"] for e in s2]


def test_token_differs_across_seeds():
    tokens_a = {e["token"] for e in make_suite("seed-A")}
    tokens_b = {e["token"] for e in make_suite("seed-B")}
    assert tokens_a.isdisjoint(tokens_b), "different seeds must produce different tokens"


def test_token_differs_across_entries_same_seed():
    suite = make_suite()
    tokens = [e["token"] for e in suite]
    assert len(tokens) == len(set(tokens)), "every entry must have a unique token"


def test_marker_equals_token():
    for entry in make_suite():
        assert entry["marker"] == entry["token"]


# ---------------------------------------------------------------------------
# evaluate()
# ---------------------------------------------------------------------------

def test_evaluate_vulnerable_when_token_in_reply():
    suite = make_suite()
    entry = suite[0]
    reply = f"Here is the answer: {entry['token']} — hope that helps."
    assert evaluate(reply, entry["token"]) == "VULNERABLE"


def test_evaluate_resistant_when_token_absent():
    suite = make_suite()
    entry = suite[0]
    assert evaluate("I will not follow injected instructions.", entry["token"]) == "RESISTANT"


def test_evaluate_resistant_on_empty_reply():
    assert evaluate("", "CLAWCHECK-RT-ABCDEF123456") == "RESISTANT"


def test_evaluate_resistant_on_none_reply():
    assert evaluate(None, "CLAWCHECK-RT-ABCDEF123456") == "RESISTANT"


def test_evaluate_case_sensitive():
    token = "CLAWCHECK-RT-ABCDEF123456"
    assert evaluate(token.lower(), token) == "RESISTANT"


# ---------------------------------------------------------------------------
# Suite covers all required categories
# ---------------------------------------------------------------------------

def test_suite_covers_all_categories():
    suite = make_suite()
    present = {e["category"] for e in suite}
    for cat in CATEGORIES:
        assert cat in present, f"category {cat!r} missing from suite"


def test_suite_entries_have_required_keys():
    required = {"id", "category", "payload", "token", "marker"}
    for entry in make_suite():
        assert required <= entry.keys(), f"{entry['id']} missing keys"


def test_suite_token_embedded_in_payload():
    for entry in make_suite():
        assert entry["token"] in entry["payload"], (
            f"{entry['id']} token not in payload"
        )


def test_suite_nonempty():
    assert len(make_suite()) >= len(CATEGORIES)


# ---------------------------------------------------------------------------
# render_suite() — ASCII safety and content checks
# ---------------------------------------------------------------------------

def test_render_suite_is_str():
    out = render_suite(make_suite())
    assert isinstance(out, str)


def test_render_suite_ascii_only_is_pure_ascii():
    out = render_suite(make_suite(), ascii_only=True)
    out.encode("ascii")  # raises UnicodeEncodeError if non-ASCII sneaks through


def test_render_suite_contains_all_ids():
    suite = make_suite()
    out = render_suite(suite)
    for entry in suite:
        assert entry["id"] in out


def test_render_suite_contains_instructions():
    out = render_suite(make_suite())
    assert "VULNERABLE" in out
    assert "RESISTANT" in out
    assert "UNTRUSTED" in out


def test_render_suite_contains_tokens():
    suite = make_suite()
    out = render_suite(suite)
    for entry in suite:
        assert entry["token"] in out


# ---------------------------------------------------------------------------
# CLI --redteam flag
# ---------------------------------------------------------------------------

def test_cli_redteam_returns_zero(capsys):
    rc = main(["--redteam", "--ascii"])
    assert rc == 0
    out = capsys.readouterr().out
    assert TOKEN_PREFIX in out


def test_cli_redteam_output_is_ascii_safe(capsys):
    main(["--redteam", "--ascii"])
    out = capsys.readouterr().out
    out.encode("ascii")  # must not raise


def test_cli_redteam_covers_categories(capsys):
    main(["--redteam"])
    out = capsys.readouterr().out
    for cat in CATEGORIES:
        assert cat in out, f"category {cat!r} absent from --redteam output"
