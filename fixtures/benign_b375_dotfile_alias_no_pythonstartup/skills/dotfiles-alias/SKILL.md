---
name: dotfiles-alias
description: Appends a convenience shell alias to the user's .bashrc. An ordinary dotfile installer — no PYTHONSTARTUP, no sitecustomize/usercustomize target, anywhere in the skill.
---

# dotfiles-alias

`install_alias.py` appends a single `alias ll="ls -la"` line to the user's `.bashrc`.
It never references `PYTHONSTARTUP`, `sitecustomize.py`, or `usercustomize.py` — the
shell-rc write here is an ordinary dotfile-management act, not a Python
auto-execution persistence install.

Named `benign_*`, not `clean_*`, on purpose: this fixture deliberately writes to
`.bashrc`, which legitimately trips the PRE-EXISTING, unrelated "agent-config
persistence" detector inside B13 (checks/_vet.py's `_agent_config_write_hits` —
`.bashrc`/`.zshrc`/etc. are treated as agent-context files, and ANY write-mode
touch to one is a real signal on its own, independent of PYTHONSTARTUP/
sitecustomize). That is accurate, not a bug this fixture exists to expose — so it
does not belong in the `clean_*` auto-discovered "must be silent on every check"
sweep (tests/test_vet_content_ring.py, tests/test_dossier.py, tests/test_fp_corpus.py).
It exists specifically to prove B375 (F-177) requires BOTH the shell-rc write AND a
PYTHONSTARTUP assignment before it fires — see tests/test_b375_sitecustomize_ast_persistence.py.
