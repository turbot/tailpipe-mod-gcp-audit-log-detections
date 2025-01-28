## Overview

Detect when the `roles/iam.serviceAccountTokenCreator` role was assigned in GCP. This role allows the creation of access tokens and impersonation of service accounts, which can lead to unauthorized access if assigned improperly. Monitoring these events ensures secure access management and prevents privilege escalation.

**References**:
- [Service Account Token Creator Role](https://cloud.google.com/iam/docs/understanding-roles#service-account-roles)
- [IAM Policy Best Practices](https://cloud.google.com/iam/docs/using-iam-securely)
- [gcloud Command: gcloud iam service-accounts add-iam-policy-binding](https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/add-iam-policy-binding)
