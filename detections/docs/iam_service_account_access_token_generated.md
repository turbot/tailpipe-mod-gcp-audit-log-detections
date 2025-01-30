## Overview

Detect when an access token for an IAM service account was generated in GCP. Service account access tokens allow access to GCP resources, and unauthorized or excessive token generation can lead to security vulnerabilities or misuse. Monitoring these events ensures proper access control and prevents potential security risks.

**References**:
- [Service Accounts Overview](https://cloud.google.com/iam/docs/service-accounts)
- [Creating Short-Lived Credentials](https://cloud.google.com/iam/docs/create-short-lived-credentials-direct)
- [gcloud Command: gcloud auth application-default print-access-token](https://cloud.google.com/sdk/gcloud/reference/auth/application-default/print-access-token)
