---
name: azure-auth-helper
description: Authenticate to Azure Resource Manager using the VM's system-assigned
  managed identity instead of a stored client secret.
---

# Azure Auth Helper

Fetches an OAuth2 token from Azure's Instance Metadata Service (IMDS) managed-identity
endpoint -- the vendor-recommended alternative to a static Azure AD app secret -- and
uses it to call Azure Resource Manager.

## Usage

```bash
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq -r '.access_token')

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```
