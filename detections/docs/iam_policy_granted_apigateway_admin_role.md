## Overview

Detect when the `roles/apigateway.admin` role was granted in GCP. This role provides full administrative access to API Gateway resources, and improper assignment can lead to unauthorized modifications or exposure of APIs. Monitoring these events ensures secure access control and prevents privilege escalation.

**References**:
- [API Gateway API access overview](https://cloud.google.com/api-gateway/docs/api-access-overview)
- [gcloud Command: gcloud projects add-iam-policy-binding](https://cloud.google.com/sdk/gcloud/reference/projects/add-iam-policy-binding)
