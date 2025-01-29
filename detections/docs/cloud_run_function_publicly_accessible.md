## Overview

Detect when a Cloud Run Function was made publicly accessible. Publicly accessible Cloud Run Functions can expose sensitive business logic or data, increasing the risk of unauthorized access or abuse. Monitoring such changes ensures that access remains restricted to authorized users only.

**References**:
- [Securing Cloud Run Functions](https://cloud.google.com/functions/docs/securing)
- [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [gcloud Command: set IAM policy](https://cloud.google.com/sdk/gcloud/reference/functions/add-iam-policy-binding)