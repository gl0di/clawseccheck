"""CLAWSECCHECK-B-986 P3: clawseccheck/curlargv.py -- real positional argv
parsing against curlgrammar.py's role table.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck import curlargv as ca
from clawseccheck import shellwords as sw


def _argv(text: str):
    """*text* is the FULL command line incl. "curl "; returns the ArgToken
    tuple for everything after the command name."""
    cmds = sw.scan_line(text)
    assert cmds is not None
    assert len(cmds) == 1
    words = cmds[0].words
    assert words[0].text == "curl"
    return ca.parse_argv(words[1:])


def _roles(text: str):
    return [t.role for t in _argv(text)]


# ---------------------------------------------------------------------------
# Basic bool/value parsing
# ---------------------------------------------------------------------------


def test_simple_bool_and_positional():
    tokens = _argv("curl -sS https://example.com")
    assert [(t.role, t.long_name) for t in tokens] == [
        ("SAFE", "--silent"),
        ("SAFE", "--show-error"),
        ("DEST", None),
    ]
    assert tokens[-1].value_text == "https://example.com"


def test_long_option_value_is_next_whole_word():
    tokens = _argv("curl --header X https://x")
    header = tokens[0]
    assert header.role == "AUTH_HEADER"
    assert header.long_name == "--header"
    assert header.value_text == "X"


def test_long_option_with_no_following_word_has_no_value():
    tokens = _argv("curl --header")
    assert tokens[0].role == "AUTH_HEADER"
    assert tokens[0].value_text is None


def test_long_option_value_consumes_next_word_even_if_flag_shaped():
    # Standard getopt-style argv semantics: a value-required option
    # unconditionally claims the NEXT word, even if it looks like a flag.
    tokens = _argv("curl -H --insecure https://x")
    header = tokens[0]
    assert header.long_name == "--header"
    assert header.value_text == "--insecure"
    # --insecure was CONSUMED as -H's value, not parsed as its own flag
    assert [t.long_name for t in tokens] == ["--header", None]


# ---------------------------------------------------------------------------
# Short option clustering / glued values
# ---------------------------------------------------------------------------


def test_clustered_bools_then_glued_value():
    tokens = _argv("curl -sSo out.txt https://x")
    assert [(t.role, t.long_name) for t in tokens] == [
        ("SAFE", "--silent"),
        ("SAFE", "--show-error"),
        ("SAFE", "--output"),
        ("DEST", None),
    ]
    assert tokens[2].value_text == "out.txt"


def test_fully_glued_cluster_value():
    tokens = _argv("curl -sSoout.txt https://x")
    assert tokens[2].long_name == "--output"
    assert tokens[2].value_text == "out.txt"


def test_glued_proxy_value():
    tokens = _argv("curl -xattacker.example.com:8080 https://x")
    proxy = tokens[0]
    assert proxy.role == "HOP"
    assert proxy.long_name == "--proxy"
    assert proxy.value_text == "attacker.example.com:8080"


def test_value_taking_short_option_ends_its_cluster():
    # -K takes a value; nothing after 'K' in this word is parsed as further
    # flags -- the rest becomes -K's own glued value.
    tokens = _argv("curl -Ksome.conf https://x")
    assert tokens[0].long_name == "--config"
    assert tokens[0].value_text == "some.conf"
    assert len(tokens) == 2  # -K token + the DEST positional only


def test_config_from_stdin_dash():
    tokens = _argv("curl -K - https://x")
    assert tokens[0].long_name == "--config"
    assert tokens[0].value_text == "-"


# ---------------------------------------------------------------------------
# Long-option prefix resolution
# ---------------------------------------------------------------------------


def test_unique_prefix_resolves():
    tokens = _argv("curl --noprox kubernetes.default.svc https://x")
    assert tokens[0].long_name == "--noproxy"
    assert tokens[0].role == "SAFE"


def test_ambiguous_prefix_is_unknown():
    tokens = _argv("curl --prox https://x")
    assert tokens[0].role == "UNKNOWN"
    assert tokens[0].long_name is None


def test_exact_match_wins_even_though_it_also_prefixes_others():
    tokens = _argv("curl --proxy https://p https://x")
    assert tokens[0].long_name == "--proxy"
    assert tokens[0].role == "HOP"


def test_unrecognized_long_option_is_unknown():
    tokens = _argv("curl --totally-not-a-real-curl-flag https://x")
    assert tokens[0].role == "UNKNOWN"


def test_no_equals_syntax_support():
    # curl itself does not support --opt=value (see curlgrammar.py); the
    # whole glued string is looked up as one (unknown) option name.
    tokens = _argv("curl --cert=/root/.config/myapp/client.pem https://x")
    assert tokens[0].role == "UNKNOWN"
    assert tokens[0].value_text is None


# ---------------------------------------------------------------------------
# Unknown short options
# ---------------------------------------------------------------------------


def test_unknown_short_option_letter():
    tokens = _argv("curl -W https://x")
    assert tokens[0].role == "UNKNOWN"
    assert tokens[0].flag_text == "-W"


def test_unknown_short_option_inside_cluster_does_not_stop_parsing():
    tokens = _argv("curl -sWS https://x")
    assert [t.role for t in tokens] == ["SAFE", "UNKNOWN", "SAFE", "DEST"]


# ---------------------------------------------------------------------------
# `--` end of options
# ---------------------------------------------------------------------------


def test_end_of_options_marker_makes_everything_positional():
    tokens = _argv("curl -sS -- --proxy https://x")
    roles = [t.role for t in tokens]
    assert roles == ["SAFE", "SAFE", "DEST", "DEST"]
    # the literal text "--proxy" is now a DEST positional, NOT a HOP flag
    assert tokens[2].value_text == "--proxy"


# ---------------------------------------------------------------------------
# --next / -:
# ---------------------------------------------------------------------------


def test_next_role_consumes_no_value():
    tokens = _argv("curl --url a --next --url b")
    roles = [(t.role, t.long_name) for t in tokens]
    assert roles == [
        ("DEST", "--url"),
        ("NEXT", "--next"),
        ("DEST", "--url"),
    ]


def test_next_short_form():
    tokens = _argv("curl --url a -: --url b")
    assert tokens[1].role == "NEXT"
    assert tokens[1].long_name == "--next"


# ---------------------------------------------------------------------------
# AUTH_HEADER / TLS_MATERIAL / CONFIG / HOP roles end to end
# ---------------------------------------------------------------------------


def test_auth_header_value_is_the_whole_quoted_word():
    tokens = _argv('curl -H "Authorization: Bearer xyz" https://x')
    header = tokens[0]
    assert header.role == "AUTH_HEADER"
    assert header.value_text == '"Authorization: Bearer xyz"'
    assert header.value_word is not None
    assert header.value_word.text == header.value_text


def test_tls_material_cacert_and_proxy_variant():
    tokens = _argv("curl --cacert ca.pem --proxy-cacert pca.pem https://x")
    assert tokens[0].role == "TLS_MATERIAL"
    assert tokens[0].long_name == "--cacert"
    assert tokens[1].role == "TLS_MATERIAL"
    assert tokens[1].long_name == "--proxy-cacert"


def test_helpers_roles_present_and_tokens_with_role():
    tokens = _argv("curl -H X --cacert ca.pem -x proxy.example.com https://x")
    present = ca.roles_present(tokens)
    assert present == {"AUTH_HEADER", "TLS_MATERIAL", "HOP", "DEST"}
    hop = ca.tokens_with_role(tokens, "HOP")
    assert len(hop) == 1
    assert hop[0].long_name == "--proxy"


# ---------------------------------------------------------------------------
# Absolute offsets stay correct against the original line text
# ---------------------------------------------------------------------------


def test_value_offsets_are_absolute_and_slice_correctly():
    text = "curl -H X https://kubernetes.default.svc/api"
    tokens = _argv(text)
    dest = tokens[-1]
    assert text[dest.value_start : dest.value_end] == "https://kubernetes.default.svc/api"


def test_glued_value_offsets_slice_correctly_from_original_line():
    text = "curl -xattacker.example.com:8080 https://x"
    tokens = _argv(text)
    proxy = tokens[0]
    assert text[proxy.value_start : proxy.value_end] == "attacker.example.com:8080"
