"""CLAWSECCHECK-B-982 -- pins the coupling between the shell HOP-role credential
vocabulary (`_SH_CRED_READ_PATH_SRC` / `_SH_CRED_READ_PATH_RE`, which feeds
`_SH_CRED_ASSIGN_RE`) and `_sh_line_incluster_exemption`'s HOP-role exemption gap.

The K8s ServiceAccount token path is in the DIRECT/PIPE vocabulary
(`_SH_CRED_FILE_RE`) but deliberately NOT in the HOP vocabulary
(`_SH_CRED_READ_PATH_SRC`). That gap is the ONLY reason a legitimate, var-based
in-cluster auth helper --

    TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
    curl -H "Authorization: Bearer ${TOKEN}" https://kubernetes.default.svc/api

-- stays SHELL_CRED_EXFIL-clean today: `_sh_cred_assign_taint_lines` (skillast.py)
never seeds `TOKEN` as tainted, because `_SH_CRED_ASSIGN_RE` never matches the read.
Not because any exemption applies -- the `cred_var_lines` sink check in
`analyze_shell` calls no exemption at all. B-986 built a real argv-parsed
in-cluster exemption (`_sh_line_incluster_exemption`), but it is DIRECT-role only
(see its own `"HOP" in roles or "CONFIG" in roles or "UNKNOWN" in roles: return
False` guard, and the "(no B-415 exemption -- the hop vocabulary has no TLS/k8s
alternative)" note above `_sh_loop_cred_exfil_lines`).

So: if the K8s token path is EVER added to `_SH_CRED_READ_PATH_SRC` -- e.g. as the
"Vocabulary alignment (design §2.5)" note above `_sh_loop_cred_exfil_lines` invites
-- without a HOP-role in-cluster exemption landing in the SAME change, the helper
above becomes a false-positive SHELL_CRED_EXFIL FAIL on correct k8s code. Dave
ruled (B-982): keep this as a documented guard; do not build the HOP exemption now.

(a) below is the exact repro via the real `analyze_shell` entry point (same shape,
same assertion, as `test_b415_k8s_incluster_auth_fp.py`'s own
`test_shell_incluster_auth_helper_not_flagged` / `_INCLUSTER_HELPER_SH` -- kept as
an independent copy here so this file is a self-contained record of the coupling,
not a claim that the other test does not already cover it). (b) is the vocabulary
tripwire itself: it fails the moment the gap it names is closed without the
exemption. The K8s ServiceAccount token PATH is not a secret VALUE, so it is used
here as a plain literal (no fragment-assembly needed, matching every neighbouring
in-cluster test in this suite).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.skillast import _SH_CRED_READ_PATH_RE, analyze_shell

_INCLUSTER_HELPER_SH = (
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n"
    'curl -sS -H "Authorization: Bearer ${TOKEN}" '
    "https://kubernetes.default.svc/api/v1/namespaces/default/pods\n"
)


def _sh_rules(src: str, filename: str = "t.sh") -> set:
    return {f.rule for f in analyze_shell(src, filename)}


def test_var_based_incluster_helper_stays_clean_pending_hop_exemption():
    """(a) The exact B-982 shape, via the real analysis entry point. Currently
    PASSES only because `_SH_CRED_READ_PATH_RE` does not match the SA token path --
    see (b) below and the module docstring this test sits under."""
    assert "SHELL_CRED_EXFIL" not in _sh_rules(_INCLUSTER_HELPER_SH)


def test_hop_vocabulary_must_not_gain_the_sa_token_path_without_an_exemption():
    """(b) Tripwire: fails the moment someone widens `_SH_CRED_READ_PATH_SRC` to
    include the K8s ServiceAccount token path -- exactly what the "Vocabulary
    alignment (design §2.5)" note above `_sh_loop_cred_exfil_lines` in
    skillast.py invites, and exactly what B-982 exists to stop from happening
    silently.

    If this assertion starts failing: add a HOP-role in-cluster exemption
    (extend `_sh_line_incluster_exemption`, or an equivalent, to cover
    `cred_var_lines` hits) in the SAME change that widens this vocabulary, then
    update this test and
    `test_var_based_incluster_helper_stays_clean_pending_hop_exemption` above to
    reflect the new, intentional behavior. Do not silence this assertion alone
    -- that is precisely the false positive B-982 documents."""
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    assert _SH_CRED_READ_PATH_RE.search(token_path) is None, (
        "the HOP vocabulary (_SH_CRED_READ_PATH_SRC) now matches the K8s "
        "ServiceAccount token path, but no HOP-role in-cluster exemption exists "
        "yet (CLAWSECCHECK-B-982) -- add the exemption in this same change "
        "before updating this test, or the var-based in-cluster auth helper "
        "above becomes a false-positive SHELL_CRED_EXFIL FAIL"
    )
