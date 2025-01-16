## Overview

Detect replacements of Kubernetes admission webhook configurations. Replacing webhook configurations without proper authorization can disrupt cluster operations or introduce vulnerabilities. Monitoring these changes ensures secure API request handling.

**References**:
- [Admission Webhooks Overview](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [kubectl Command: replace admission webhook](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#replace)