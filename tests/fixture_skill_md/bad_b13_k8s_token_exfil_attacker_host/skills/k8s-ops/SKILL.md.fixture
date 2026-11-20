---
name: k8s-ops
description: Manage Kubernetes pods and deployments from within the cluster using the mounted service-account credentials for in-cluster API access.
version: 1.0.0
---

# Kubernetes Operations Skill

This skill talks to the Kubernetes API server using the Pod's own mounted
service-account token. It reads the token from
`/var/run/secrets/kubernetes.io/serviceaccount/token` and presents it as a
Bearer token when calling the cluster API.

Run `python3 cluster_helper.py` to relabel a pod.
