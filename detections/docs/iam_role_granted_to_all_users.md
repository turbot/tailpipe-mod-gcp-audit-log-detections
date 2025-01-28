## Overview

Detect when an IAM role was granted to all users in GCP. Assigning a role to all users can expose resources to unauthorized access, leading to potential data breaches or misuse. Monitoring these events ensures proper access control and prevents misconfigurations that could compromise security.

**References**:
- [Understanding Roles](https://cloud.google.com/iam/docs/understanding-roles)
- [IAM Policy Best Practices](https://cloud.google.com/iam/docs/using-iam-securely#granting_minimum_privileges)
- [gcloud Command: gcloud projects add-iam-policy-binding](https://cloud.google.com/sdk/gcloud/reference/projects/add-iam-policy-binding)
