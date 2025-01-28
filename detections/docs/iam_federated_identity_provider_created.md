## Overview

Detect when an IAM federated identity provider was created in GCP. Federated identity providers enable external identities to access GCP resources, and unauthorized or unintended creation of these providers can introduce security risks. Monitoring these events ensures proper access control and prevents unauthorized integrations.

**References**:
- [Managing Identity Providers](https://cloud.google.com/iam/docs/workload-identity-federation)
- [gcloud Command: gcloud iam workload-identity-pools providers create](https://cloud.google.com/sdk/gcloud/reference/iam/workload-identity-pools/create)
