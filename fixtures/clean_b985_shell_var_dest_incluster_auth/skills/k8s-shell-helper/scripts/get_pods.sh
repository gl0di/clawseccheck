#!/usr/bin/env bash
# Lists pods in the default namespace using the pod's own mounted
# service-account token -- the standard, documented way for a pod-resident
# tool to talk to its own cluster's control plane (see SKILL.md).
set -euo pipefail

API_SERVER="https://kubernetes.default.svc"
curl -sS \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  "${API_SERVER}/api/v1/namespaces/default/pods"
