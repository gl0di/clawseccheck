"""A config that states its own security posture instead of inheriting OpenClaw's.

Several exit-code and layer-state tests wrote `{}` and asserted "this run exits 0". That
made the assertion depend on whatever OpenClaw happens to be installed on the machine
running the suite, which is not a property those tests are about — and it broke the day a
vendor default flipped: OpenClaw 2026.8.1 ships `skills.workshop.autonomous.mode: "auto"`
and `approvalPolicy: "auto"` where 2026.7.x shipped `enabled: false` / `"pending"`, so B175
correctly FAILs at HIGH on an empty config (B-702) and every "safe config exits 0" test on
an 8.1 box went red.

The check is right and must not be softened — the default really is unattended authoring
plus unattended install. What was wrong is a fixture that meant "nothing dangerous is
configured" and wrote "whatever the vendor decided this month".

So: write the safe value explicitly. Values grounded in `checks/_lifecycle.py`'s B175 block,
which took them from each build's own `src/skills/workshop/config.ts` — `mode: "off"` keeps
only the suggestion nudge, and `"pending"` is the review-gated policy. `enabled: false` is
carried alongside `mode` because 2026.7.x reads the boolean and 8.1 reads the enum, and a
test fixture should be neutral on both builds rather than on the one under our feet.

Extend this when a NEW vendor default turns dangerous — that is the point of having one
place. Do not use it to silence a finding about something a test is actually testing.
"""

VENDOR_NEUTRAL_CONFIG = {
    "skills": {
        "workshop": {
            "autonomous": {"mode": "off", "enabled": False},
            "approvalPolicy": "pending",
        }
    }
}


def neutral_config(**overrides):
    """The neutral base, deep-merged with whatever the test actually wants to say."""
    import copy

    cfg = copy.deepcopy(VENDOR_NEUTRAL_CONFIG)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            cfg[key] = {**cfg[key], **value}
        else:
            cfg[key] = value
    return cfg
