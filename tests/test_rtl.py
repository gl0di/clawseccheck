"""RTL formatting of the plain-text report (--lang he).

The text report wraps every embedded LTR token (English field names, codes, paths,
numbers) in a bidi isolate and prefixes each line with RLM, so RTL chat clients /
terminals render mixed Hebrew+English lines without scrambling. Only safe isolate
marks are added, and only after untrusted evidence has already been bidi-stripped.
"""
from clawseccheck import audit
from clawseccheck.report import render_report

_RLM = "‏"
_LRI = "⁦"
_PDI = "⁩"


def _he_report():
    _, findings, score = audit("fixtures/home_vuln")
    return render_report(findings, score, lang="he")


def test_he_report_has_rtl_marks():
    out = _he_report()
    assert _RLM in out          # base-direction marker present
    assert _LRI in out and _PDI in out  # LTR tokens isolated


def test_he_isolates_are_balanced():
    out = _he_report()
    assert out.count(_LRI) == out.count(_PDI)  # every isolate is closed


def test_he_ltr_token_is_wrapped():
    out = _he_report()
    # an English config token must appear inside an isolate
    assert _LRI + "gateway" in out or _LRI + "tools" in out or _LRI + "SOUL" in out


def test_he_every_nonblank_line_starts_with_rlm():
    out = _he_report()
    for line in out.split("\n"):
        if line.strip():
            assert line.startswith(_RLM), repr(line[:30])


def test_en_report_has_no_rtl_marks():
    _, findings, score = audit("fixtures/home_vuln")
    out = render_report(findings, score, lang="en")
    assert _RLM not in out and _LRI not in out and _PDI not in out


def test_he_ascii_only_has_no_bidi_marks():
    # ascii mode can't carry unicode bidi marks; it must stay pure ASCII.
    _, findings, score = audit("fixtures/home_vuln")
    out = render_report(findings, score, lang="he", ascii_only=True)
    assert _RLM not in out and _LRI not in out and _PDI not in out
    out.encode("ascii")  # must not raise


def test_he_content_intact_after_stripping_marks():
    out = _he_report().replace(_RLM, "").replace(_LRI, "").replace(_PDI, "")
    # Hebrew chrome + an English field name both survive
    assert "מדוע:" in out
    assert "gateway" in out
