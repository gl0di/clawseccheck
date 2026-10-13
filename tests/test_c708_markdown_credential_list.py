"""C-708: C015 must convict a markdown credential list (`- **Password:** `value``).

Measured on a real home: `workspace/PASSWORDS.md` was scanned (C-700) but not reported, because the
shared keyword pattern `(password|secret|api[_-]?key|token)\\s*[:=]\\s*['"]?(\\S{8,})` captures the
closing bold marker `**` that sits between the colon and the value. The shared `SECRET_PATTERNS`
are deliberately NOT widened (B1, A1 and the log redactor read them, and widening convicts benign
placeholders); the shape is convicted in C015 only.

The rules are structural, not word lists (a substring list rejected the real password
`Contest2024!x` because of "test"):

* label: the markup `**L:**` / `**L**:` / `*L:*` / `__L:__`, split on whitespace, `_`, `-`; its LAST
  word is password / passphrase / passcode / secret / token, or its last two words are api key /
  private key / secret key / access key; at most 5 words;
* value: one code span right after the label, or the whole rest of the line as one token;
  ASCII printable, 8-128 characters;
* real-secret rule: a letter and a digit-or-symbol; not a reference, an ALL-CAPS identifier, a
  mask, a URL or path, code, hyphen/underscore prose, or a whole-token placeholder word.

Every secret-shaped value is assembled at runtime from fragments.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_secrets_at_rest_home
from clawseccheck.collector import Context

_V = "Zk3demo" + "Value91" + "!"
_V2 = "Zk3" + "-demo-" + "Value" + "-91"
_H = "ab12" + "CD34" + "ef56" + "GH78"
_HEX = "9f" + "3a" * 11 + "c1"
_ADDR = "0x" + "ab12" * 10
_LONG = "Zk3d" * 32


def _fill(template: str) -> str:
    out = template
    for key, val in (("@V2@", _V2), ("@V@", _V), ("@H@", _H), ("@HEX@", _HEX), ("@ADDR@", _ADDR),
                     ("@LONG@", _LONG)):
        out = out.replace(key, val)
    return out


def _hit(text: str) -> bool:
    from clawseccheck.checks import _c015_md_credential_list_hit

    return _c015_md_credential_list_hit(text)


# (line, expected). A line is what a note file holds; "@V@" etc. are runtime-assembled values.
_CONVICTED = [
    # the three shapes the task names
    "- **Password:** `@V2@`",
    "**Password**: @V@",
    "*API key:* `@H@`",
    "- **Login / email:** `someone`\n- **Password:** `@V2@`\n- **Website:** https://x.test/",
    # label markup and prefixes
    "* **Secret**: `@V@`",
    "  1. **Token:** @HEX@",
    "__Passphrase:__ @V@",
    "- *Token*: @HEX@\r",
    "> **Password:** `@V@`",
    ">> **Password:** `@V@`",
    "- [ ] **Password:** `@V@`",
    "- [x] **Password:** `@V@`",
    "    **Password:** @V@",
    "- **PASSWORD**: `@V@`",
    "- **Password** : `@V@`",
    # labels that end in a credential noun
    "- **DB_PASSWORD:** `@V@`",
    "- **GITHUB_TOKEN:** `@V@`",
    "- **OPENAI_API_KEY:** `@H@`",
    "- **API_KEY:** `@H@`",
    "- **client_secret:** `@V@`",
    "- **gateway-token:** `@V@`",
    "- **Admin password:** `@V2@`",
    "- **Bearer token:** @V@",
    "- **Client secret:** `@V@`",
    "- **Passcode:** `@V@`",
    "- **Private key:** `@V@`",
    "- **Secret key:** `@V@`",
    "- **Access key:** `@V@`",
    "- **Wi-Fi password:** `@V@`",
    "- **The admin root user password:** `@V@`",
    # value shapes
    "- **Password:** `@V@` (change after first login)",
    "- **Password:** `Zk3demo!`",
    "- **Password:** `@LONG@`",
    "- **API key:** `sk-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv" + "`",
    "- **Password:** `Contest2024!x`",
    "- **Password:** `MyTest#2024pw`",
    "- **Password:** `Vault!9x7Kq`",
    "- **Password:** `Mastodon#12Qk`",
    "- **Password:** `Winter2024###`",
    "- **Password:** `Zk3/demo/Value.91`",
    "- **Password:** `ab/cd#12XY!zz`",
    "- **Password:** `Pa$$w0rd!x9`",
    "- **Password:** `Zk3www.Value91`",
    "- **Token:** `a1b2c3d4-e5f6-7890-abcd-ef1234567890`",
    # a dot is a symbol: a dotted passphrase is not letters-only
    "- **Password:** `Correct.Horse.Battery`",
]

_NOT_CONVICTED = [
    # label does not end in a credential noun
    "- **Token expires:** 2026-10-13T10:00:00Z",
    "- **Token scope:** read:user",
    "- **Token budget:** 200k/session",
    "- **Token Prefixes:** `sk-abc123xy`",
    "- **Token type:** `Bearer-JWT-2`",
    "- **Password rotation:** every-90-days",
    "- **Password policy:** `@V@`",
    "- **Secret name:** db-creds",
    "- **Passwords:** `@V@`",
    "- **Credentials:** `@V@`",
    "- **Strict secret-file durability:** `createSecretFileAtomic()`",
    "- **Safer secret and private writes:** `@H@`",
    "- **Login / email:** `@V@`",
    "- **Website:** `@V@`",
    "- **Tokenizer:** `@V@`",
    "- **Secretary:** `@V@`",
    "- **BOTCOIN token address:** @ADDR@",
    "- **The one admin root user password:** `@V@`",
    "- **Pass word:** `@V@`",
    "- **githubToken:** `@V@`",
    # no markup, or markup the rule does not read
    "Password: @V@",
    "| Password | `@V@` |",
    "| **Password** | `@V@` |",
    "| **Password:** | `@V@` |",
    "## **Password:** `@V@`",
    "<b>Password:</b> @V@",
    "- **Mot de passe:** `@V@`",
    "- **Пароль:** `@V@`",
    "- **Password:**\n  `@V@`",
    "**Password: @V@**",
    "- **Password** - `@V@`",
    "- **Password** = `@V@`",
    "- **Password** is `@V@`",
    "- **Login:** user / **Password:** `@V@`",
    "- \U0001f511 **Password:** `@V@`",
    "- **Password：** `@V@`",
    "## Password policy\n\nUse a long, random passphrase.",
    "The **Password** is kept in the team vault.",
    # value is not one code span / one lone token, or is the wrong size or alphabet
    "- **Password:**",
    "- **Password:** ",
    "- **Password:** ``",
    "- **Password:** `` @V@",
    "- **Password:** `@V@",
    "- **Password:** @V@ (change after first login)",
    "- **Password:** '@V@'",
    '- **Password:** "@V@"',
    "- **Password:** see the vault",
    "- **Token:** see the vault",
    "- **Password:** `Zk3 demo Value91`",
    "- **Password:** `Zk3dem!`",
    "- **Password:** `@LONG@x`",
    "- **Token:** `不可猜测的随机字符串`",
    "- **Token:** `" + _V + "é`",
    # not a real secret: letters only, digits only, masks, references, identifiers
    "- **Password:** `CorrectHorseBatteryStaple`",
    "- **Password:** `correct-horse-battery-staple`",
    "- **Password:** `48151623`",
    "- **Password:** `4815-1623-42`",
    "- **Password:** `********`",
    "- **Password:** `xxxxxxxx`",
    "- **Password:** `Hello2024...`",
    "- **Password:** `Zk3***Value91`",
    "- **Password:** `sk-****abcd1234`",
    "- **Password:** `Zk3aaaaValue91`",
    "- **Password:** `${GATEWAY_PASSWORD}`",
    "- **Password:** `$GATEWAY_PASSWORD`",
    "- **Password:** `<your-password-here>`",
    "- **Password:** `{{gateway_password}}`",
    "- **Password:** `%GATEWAY_PASSWORD%`",
    "- **Password:** `secretref-env:GATEWAY_PASSWORD`",
    "- **Token:** `OPENCLAW_GATEWAY_TOKEN`",
    "- **Password:** `HUNTER2PASS99`",
    # URLs, paths, addresses, code, flags
    "- **Password:** `https://x.test/t/Ab12Cd34`",
    "- **Password:** `/etc/openclaw/secrets/gateway.token`",
    "- **Password:** `~/.config/openclaw/token.txt`",
    "- **Password:** `./secrets/Ab12Cd34.txt`",
    "- **Password:** `../secrets/Ab12Cd34.txt`",
    "- **Token:** @ADDR@",
    "- **Token:** `[your_token]`",
    '- **API key:** `os.environ["OPENAI_API_KEY"]`',
    "- **Token:** `createSecretFileAtomic()`",
    "- **Token:** `--chain-name`",
    "- **Token:** `-Zk3demoValue91`",
    # hyphen / underscore prose
    "- **Password:** `every-90-days`",
    "- **API key:** `stored-in-1password-vault`",
    "- **Password:** `auto-generated-on-first-run`",
    "- **Password:** `rotate_every_ninety_days`",
    "- **Password:** `1password-item-x`",
    "- **Password:** `your-password-here`",
    # a placeholder word as a WHOLE token
    "- **Password:** `Zk3.example.91x`",
    "- **Password:** `Zk3_here_91x`",
    "- **Password:** `Zk3-token-91`",
    "- **Password:** `Zk3-changeme-1`",
    "- **Password:** `sample-Zx81!kk`",
]


@pytest.mark.parametrize("line", _CONVICTED, ids=[f"conv{i:02d}" for i in range(len(_CONVICTED))])
def test_markdown_credential_line_is_convicted(line):
    assert _hit(_fill(line) + "\n") is True, line


@pytest.mark.parametrize("line", _NOT_CONVICTED, ids=[f"clean{i:03d}" for i in range(len(_NOT_CONVICTED))])
def test_markdown_line_that_is_not_a_credential_is_not_convicted(line):
    assert _hit(_fill(line) + "\n") is False, line


def test_a_decoy_placeholder_line_does_not_mask_a_real_one():
    text = "- **Password:** `<your-password>`\n- **Token:** `" + _H + "`\n"
    assert _hit(text) is True


def test_unterminated_backtick_is_not_a_credential_value():
    # a broken code span is not a value the rule can delimit: declared limit, not a conviction
    assert _hit("- **Password:** `" + _V) is False
    assert _hit("- **Password:** " + "`" * 50 + "\n") is False


def test_a_whole_file_is_scanned_not_only_its_first_line():
    body = "# Notes\n\nSee the vault.\n\n- **Token expires:** 2026-10-13\n- **Password:** `" + _V + "`\n"
    assert _hit(body) is True
    assert _hit(body.replace(_V, "<your-password>")) is False


def test_the_convicted_lines_are_reported_with_label_and_value():
    from clawseccheck.checks import _c015_md_credential_lines

    text = "x\n- **Token expires:** 2026-10-13\n- **GITHUB_TOKEN:** `" + _V + "`\n"
    assert list(_c015_md_credential_lines(text)) == [(3, "GITHUB_TOKEN", _V)]


def test_pathological_lines_finish_and_are_not_convicted():
    assert _hit("- " * 100_000 + "\n") is False
    assert _hit("> " * 100_000 + "**\n") is False
    assert _hit("**" + "a " * 50_000 + "\n") is False
    assert _hit("*" * 100_000 + "\n") is False


def test_shared_secret_patterns_are_not_widened():
    """The shape must not leak into the shared detector B1, A1 and the redactor read."""
    from clawseccheck.checks import SECRET_PATTERNS, _c015_has_secret, _pattern_hits_real_secret

    text = "- **Password:** `" + _V2 + "`\n"
    assert _pattern_hits_real_secret(SECRET_PATTERNS, text) is False
    assert _c015_has_secret(text) is False


# ---------------------------------------------------------------- wiring: the C015 check itself
def _home_with(tmp_path: Path, rel: str, body: str) -> Context:
    home = tmp_path / "home"
    target = home / rel
    target.parent.mkdir(parents=True)
    target.write_text(body, encoding="utf-8")
    ctx = Context(home=home)
    ctx.config = {}
    return ctx


def test_c015_warns_on_a_markdown_password_note_in_the_workspace(tmp_path):
    body = (
        "# Accounts\n\n- **Login / email:** `someone`\n"
        "- **Password:** `" + _V2 + "`\n- **Website:** https://x.test/\n"
    )
    f = check_secrets_at_rest_home(_home_with(tmp_path, "workspace/PASSWORDS.md", body))
    assert f.status == WARN
    assert any("workspace/PASSWORDS.md" in e for e in f.evidence)
    assert _V2 not in f.detail + f.fix + " ".join(f.evidence)


def test_c015_passes_on_a_markdown_note_holding_only_placeholders(tmp_path):
    body = (
        "- **Password:** `<your-password>`\n- **Token:** `OPENCLAW_GATEWAY_TOKEN`\n"
        "- **API key:** `stored-in-1password-vault`\n- **Token expires:** 2026-10-13T10:00:00Z\n"
    )
    f = check_secrets_at_rest_home(_home_with(tmp_path, "workspace/PASSWORDS.md", body))
    assert f.status == PASS


# Round 3: the survey of 273,801 markdown files left three benign shapes; each is pinned here.
@pytest.mark.parametrize("value", ["USDC/WETH", "local-ollamamodel", "{api_key}", "{{token}}", "CorrectHorseBatteryStaple"])
def test_a_name_without_a_digit_and_with_few_character_kinds_is_not_a_secret(value):
    from clawseccheck.checks import _c015_md_credential_list_hit, _c015_md_value_is_real_secret

    assert not _c015_md_value_is_real_secret(value)
    assert not _c015_md_credential_list_hit(f"- **Token:** `{value}`")


def test_a_symbol_rich_value_without_a_digit_is_still_a_secret():
    from clawseccheck.checks import _c015_md_credential_list_hit

    value = "Passw" + "@rd" + "!xQ"        # lower, upper and symbol: three kinds, no digit
    assert _c015_md_credential_list_hit(f"- **Password:** `{value}`")
