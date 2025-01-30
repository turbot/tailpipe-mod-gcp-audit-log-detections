## Overview

Detect when an IAM service account key was deleted in GCP. Deleting a service account key can impact applications or services relying on that key for authentication, potentially causing disruptions. Monitoring these events ensures secure key management and prevents unauthorized or accidental removal of critical keys.

**References**:
- [Service Account Keys Overview](https://cloud.google.com/iam/docs/service-account-creds#key-types)
- [Best Practices for Managing Service Account Keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)
- [gcloud Command: gcloud iam service-accounts keys delete](https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/keys/delete)
