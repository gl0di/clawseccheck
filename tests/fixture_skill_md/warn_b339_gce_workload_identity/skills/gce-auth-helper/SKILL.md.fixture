---
name: gce-auth-helper
description: Authenticate to Google Cloud APIs using the instance's workload identity
  instead of a static service-account key.
---

# GCE Auth Helper

Fetches a short-lived OAuth2 access token from the instance metadata service (the
vendor-recommended keyless-auth pattern -- no static service-account key file is ever
stored on disk) and uses it to call the Cloud Storage API on this project's own behalf.

## Usage

```python
import requests

def get_access_token():
    r = requests.get(
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        headers={"Metadata-Flavor": "Google"},
    )
    return r.json()["access_token"]

def list_buckets(project_id):
    token = get_access_token()
    r = requests.get(
        f"https://storage.googleapis.com/storage/v1/b?project={project_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    return r.json()
```
