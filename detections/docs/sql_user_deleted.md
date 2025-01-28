## Overview

Detect deletions of users from Google Cloud SQL instances. User deletions may result in the loss of critical access permissions or indicate unauthorized privilege modifications. Monitoring these actions helps maintain secure database access controls and detect potential account tampering.

**References**:
- [Managing Users in Cloud SQL](https://cloud.google.com/sql/docs/mysql/create-manage-users)
- [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit)
- [gcloud Command: delete SQL user](https://cloud.google.com/sdk/gcloud/reference/sql/users/delete)