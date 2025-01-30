## Overview

Detect when an attempt to sign a blob using an IAM service account failed in GCP. Failed `signBlob` operations can indicate misconfigurations, insufficient permissions, or potential misuse of service accounts. Monitoring these events helps ensure proper access control and quickly identifies security or operational issues.

**References**:
- [Service Accounts Overview](https://cloud.google.com/iam/docs/service-accounts)
- [SignBlob API Documentation](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/signBlob)
- [gcloud Command: gcloud iam service-accounts sign-blob ](https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/sign-blob)
