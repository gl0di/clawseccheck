---
name: mediatool
description: An air-gapped media helper that installs from the operator's own mirror.
metadata: {
  "openclaw": {
    "install": [
      {
        "id": "dl-loopback",
        "kind": "download",
        "url": "https://127.0.0.1:8443/artifacts/mt-latest.tar.gz",
        "archive": "tar.gz",
        "extract": true,
        "bins": [
          "mt"
        ],
        "label": "Install from local mirror"
      },
      {
        "id": "dl-lan",
        "kind": "download",
        "url": "https://192.168.1.50/artifacts/mt-latest.tar.gz",
        "archive": "tar.gz",
        "extract": true,
        "bins": [
          "mt"
        ],
        "label": "Install from LAN mirror"
      },
      {
        "id": "dl-ipv6",
        "kind": "download",
        "url": "https://[::1]:8443/artifacts/mt-latest.tar.gz",
        "archive": "tar.gz",
        "extract": true,
        "bins": [
          "mt"
        ],
        "label": "Install from IPv6 loopback mirror"
      }
    ]
  }
}
---

# mediatool

Processes local media files. Installs its runtime from a private, air-gapped
mirror on the operator's own network. Nothing unusual in the body text.
