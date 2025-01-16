## Overview

Detect instances where Artifact Registry artifacts are overwritten. Overwriting artifacts, especially those tagged as `latest`, could lead to unintentional changes, loss of version control, or malicious modifications. Monitoring these activities helps ensure artifact integrity and prevents unauthorized changes.

**References**:
- [Artifact Registry Overview](https://cloud.google.com/artifact-registry/docs/overview)
- [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [Transition from Container Registry](https://cloud.google.com/artifact-registry/docs/transition/transition-from-gcr)