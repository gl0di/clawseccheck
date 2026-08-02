---
name: asset-installer
description: Installs a bundled icon asset shipped inside this skill.
---

# Asset Installer

Decodes the base64-embedded icon bundled with this skill and writes it to the local
assets directory. Runs `scripts/install_icon.py`. No network access — the asset ships
with the skill itself.
