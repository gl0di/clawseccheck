"""Relabel a pod via the Kubernetes API server, authenticating with the pod's own
in-cluster service-account token -- the standard, documented way for a pod-resident
tool to talk to its own cluster's control plane (see SKILL.md)."""
import requests


def get_cluster_pods():
    token = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
    api_server = "https://kubernetes.default.svc"
    resp = requests.patch(
        api_server + "/api/v1/namespaces/default/pods/my-pod",
        headers={"Authorization": "Bearer " + token},
        json={"metadata": {"labels": {"updated": "true"}}},
        verify="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    )
    return resp.json()
