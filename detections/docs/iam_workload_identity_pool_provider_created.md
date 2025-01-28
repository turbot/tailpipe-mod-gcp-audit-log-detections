## Overview

Detect when an IAM workload identity pool provider was created in GCP. Workload identity pool providers allow external identities to access GCP resources, and unauthorized or unintended creation of these providers can introduce security vulnerabilities. Monitoring these events ensures proper governance and prevents unauthorized integrations.

**References**:
- [Workload Identity Federation Overview](https://cloud.google.com/iam/docs/workload-identity-federation)
- [gcloud Command: gcloud iam workload-identity-pools providers create-oidc](https://cloud.google.com/sdk/gcloud/reference/iam/workload-identity-pools/providers/create-oidc)
