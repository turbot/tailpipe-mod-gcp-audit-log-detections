## Overview

Detect when a logging bucket was deleted in GCP. Logging buckets store logs for analysis and compliance, and their deletion can result in the loss of critical log data, impacting monitoring and forensic investigations. Monitoring these events ensures the integrity and availability of log storage and prevents unauthorized or accidental deletions.

**References**:
- [Cloud Logging Buckets Overview](https://cloud.google.com/logging/docs/buckets)
- [Best Practices for Managing Logging Buckets](https://docs.cadosecurity.com/cado/deploy/gcp/logs)
- [gcloud Command: gcloud logging buckets delete](https://cloud.google.com/sdk/gcloud/reference/logging/buckets/delete)