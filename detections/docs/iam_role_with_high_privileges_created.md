## Overview

Detect when an IAM role with high privileges was created in GCP. High-privilege roles grant extensive access to resources and their improper creation can introduce security risks or lead to privilege escalation. Monitoring these events ensures adherence to the principle of least privilege and prevents unauthorized or excessive access.

**References**:
- [Understanding Roles](https://cloud.google.com/iam/docs/understanding-roles)
- [IAM Policy Best Practices](https://cloud.google.com/iam/docs/using-iam-securely)
- [gcloud Command: gcloud iam roles create](https://cloud.google.com/sdk/gcloud/reference/iam/roles/create)
