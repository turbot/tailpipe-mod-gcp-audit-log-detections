## Overview

Detect deletions of Kubernetes cronjobs. Cronjobs schedule critical tasks, and their unauthorized or accidental deletion can disrupt operations or indicate malicious activity. Monitoring these actions ensures the integrity of task scheduling.

**References**:
- [Kubernetes Cronjobs Overview](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)
- [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [kubectl Command: delete cronjob](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#delete)