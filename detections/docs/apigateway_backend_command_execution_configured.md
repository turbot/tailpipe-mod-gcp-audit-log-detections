## Overview

Detect instances where an API Gateway is configured to execute backend commands. Such configurations might unintentionally expose critical backend resources or allow unauthorized command execution, leading to potential security vulnerabilities. Monitoring these configurations ensures secure API Gateway setups and minimizes exposure to threats.

**References**:
- [API Gateway Overview](https://cloud.google.com/api-gateway/docs/overview)
- [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [gcloud Command: update API config](https://cloud.google.com/sdk/gcloud/reference/api-gateway/api-configs/update)