## v0.3.0 [2025-03-03]

_Enhancements_

- Added `title`, `description`, and `folder = "Project"` tag to `Activity Dashboard` queries for improved organization and clarity. ([#7](https://github.com/turbot/tailpipe-mod-gcp-audit-log-detections/pull/7))
- Added `folder = "<service>"` tag to `service common tag locals` for better query categorization. ([#7](https://github.com/turbot/tailpipe-mod-gcp-audit-log-detections/pull/7))
- Standardized all queries to use `service common tags`, ensuring consistency across detection queries. ([#7](https://github.com/turbot/tailpipe-mod-gcp-audit-log-detections/pull/7))

## v0.3.0 [2025-02-14]

_Enhancements_

- Added `operation_src` and `resource_src` columns to retain original log data with consistent column naming.

## v0.2.0 [2025-02-06]

_Enhancements_

- Added documentation for `activity_dashboard` dashboard. ([#4](https://github.com/turbot/tailpipe-mod-gcp-audit-log-detections/pull/4))

## v0.1.0 [2025-01-30]

_What's new?_

- New benchmarks added:
  - Audit Log Detections benchmark (`powerpipe benchmark run gcp_audit_log_detections.benchmark.audit_log_detections`).
  - MITRE ATT&CK v16.1 benchmark (`powerpipe benchmark run gcp_audit_log_detections.benchmark.mitre_attack_v161`).

- New dashboards added:
  - [Audit Log Activity Dashboard](https://hub.powerpipe.io/mods/turbot/gcp_audit_log_detections/dashboards/dashboard.activity_dashboard)
