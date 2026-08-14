"""B-534: a bare persistence path convicts in either direction. Residual, not fixed.

`_CRON_PERSIST_RE` anchors on a verb for every alternative except two — `Library/LaunchAgents`
and `.config/systemd/user/*.service` are bare paths. Copying plists OUT of the launch-agent
directory (a backup) therefore reads as installing one, and B13 FAILs a clean skill.

A directional fix was written and RETRACTED. It skipped a match that was not the final path
token on a `cp`/`mv`/`rsync`/`install`/`scp` line. An independent adversarial pass killed it:
`_SHELL_PATH_TOKEN_RE` splits on `[^\\s;|&]+`, which does not treat `>` as a separator, so
`2>/dev/null` survives as one token and becomes "the destination". Appending that to a genuine
install silenced it. Measured, 4 of 5 install shapes bypassed — and `2>/dev/null` is among the
most common trailing constructs in shell, malicious ones included.

Two further holes in the same idea, both real: GNU `cp -t DEST src` / `install -t DEST src` put
the destination FIRST, so "last token is the destination" is exactly backwards; and a quoted
destination containing a space (`"$HOME/Library/LaunchAgents/My Agent.plist"`) tokenises into
pieces, pushing the persistence path out of final position. Deciding this properly needs real
shell tokenisation, not a path-position heuristic.

So the false positive stands, and this file pins BOTH sides of it: the FP that is accepted for
now, and the install shapes any future fix must never silence. The project rule that made the
call is that a false positive is never fixed by opening a false negative.
"""
import pytest

from clawseccheck.checks._vet import _cron_persistence_hits


def fails(blob: str) -> bool:
    high, _ = _cron_persistence_hits(blob, [])
    return bool(high)


# ------------------------------------------------------- the accepted false positive

@pytest.mark.parametrize("blob", [
    'cp ~/Library/LaunchAgents/com.openclaw.*.plist "$PROTON/Vault/config/launchagents/" 2>/dev/null',
    "rsync -a ~/Library/LaunchAgents/ /backup/agents/",
    "cp ~/.config/systemd/user/agent.service /backup/",
    "ls -la ~/Library/LaunchAgents/",
    "tar -czf backup.tgz ~/Library/LaunchAgents",
])
def test_reading_a_persistence_path_still_false_fails(blob):
    """Accepted residual, from `proton-drive-backup` (SkillTrustBench case_04768, gold normal).

    Reading or archiving the launch-agent directory is a backup, not an install, and the check
    cannot tell the difference. When someone fixes this, these assertions flip — that is the
    point of pinning them. Note the FP class is wider than copies: `ls` and `tar` are here too,
    which the retracted copy-only fix would not have touched either.
    """
    assert fails(blob)


# --------------------------------------------- what a future fix must never silence

@pytest.mark.parametrize("blob", [
    "cp /tmp/a.plist ~/Library/LaunchAgents/com.evil.plist",
    "cp /tmp/a.plist ~/Library/LaunchAgents/com.evil.plist 2>/dev/null",
    "cp e.plist ~/Library/LaunchAgents/x.plist && echo ok",
    "cp -t ~/Library/LaunchAgents/ /tmp/evil.plist",
    "install -m 644 -t ~/.config/systemd/user/evil.service /tmp/evil.service",
    'cp evil.plist "$HOME/Library/LaunchAgents/My Agent.plist"',
    "launchctl load ~/Library/LaunchAgents/com.evil.plist",
    "cat payload > ~/Library/LaunchAgents/com.evil.plist",
])
def test_genuine_installs_must_always_convict(blob):
    """The adversarial set that killed the first fix attempt. Every one of these is a real
    launch-agent install; the retracted heuristic silenced four of them. Any future attempt at
    B-534 has to keep this list green — that is the trap this file exists to be."""
    assert fails(blob), "a real persistence install must never be suppressed"
