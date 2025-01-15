// Benchmarks and controls for specific services should override the "service" tag
locals {
  gcp_audit_log_detections_common_tags = {
    category = "Detection"
    plugin   = "gcp"
    service  = "GCP/AuditLog"
  }
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  detection_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  method_name as operation,
  __RESOURCE_SQL__ as resource,
  authentication_info.principal_email as actor,
  tp_source_ip as source_ip,
  tp_index as project,
  tp_id as source_id,
  *
  EOQ

  detection_sql_where_conditions = <<-EOQ
    and severity != 'Error'
    -- and (operation is null or operation.last = true)
  EOQ
  // Keep same order as SQL statement for easier readability
  detection_display_columns = [
    "timestamp",
    "operation",
    "resource",
    "actor",
    "source_ip",
    "project",
    "source_id"
  ]
}
