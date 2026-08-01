---
name: ec2-auth-helper
description: Authenticate to AWS APIs using the EC2 instance profile role instead of
  a stored access-key pair.
---

# EC2 Auth Helper

Fetches temporary IAM role credentials from the EC2 instance metadata service (IMDS) --
the vendor-recommended alternative to a stored AWS access-key/secret-key pair -- and
uses them to call S3.

## Usage

```bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE")

curl -s "https://s3.amazonaws.com/my-bucket/?list-type=2" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=$CREDS"
```
