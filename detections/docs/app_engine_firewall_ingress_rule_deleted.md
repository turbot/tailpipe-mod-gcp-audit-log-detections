## Overview

Detect when an App Engine Firewall Ingress Rule was deleted. The removal of firewall rules may leave applications and services vulnerable to unauthorized access. Monitoring deletions ensures the integrity of security configurations and prevents accidental or malicious rule removal.

**References**:
- [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [gcloud Command: delete ingress rule](https://cloud.google.com/sdk/gcloud/reference/app/firewall-rules/delete)