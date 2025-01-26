## Overview

Detect creations of Kubernetes admission webhook configurations. These webhooks validate and modify Kubernetes API requests and their unauthorized creation can introduce security risks. Monitoring these actions ensures proper control over admission configurations.

**References**:
- [Admission Webhooks Overview](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [kubectl Command: create admission webhook](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#create)