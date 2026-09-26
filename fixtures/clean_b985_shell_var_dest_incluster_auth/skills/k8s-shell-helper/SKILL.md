---
name: k8s-shell-helper
description: Relabel a Kubernetes pod from within the cluster using the pod's own mounted service-account token for in-cluster API access.
version: 1.0.0
---

# Kubernetes Shell Helper

This skill talks to the Kubernetes API server using the Pod's own mounted
service-account token (the standard in-cluster authentication mechanism
documented by Kubernetes itself). The API server address is kept in a shell
variable and referenced when building the request URL.

Run `bash scripts/get_pods.sh` to list pods in the default namespace.
