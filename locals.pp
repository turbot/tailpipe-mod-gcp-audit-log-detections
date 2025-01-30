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
  -- Create new aliases to preserve original row data
  *
  EOQ

  detection_sql_where_conditions = <<-EOQ
    and severity != 'Error'
    -- TODO: Do we need to check operation?
    -- and (operation_src is null or operation_src.last = true)
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

locals {
  detection_sql_resource_column_resource_name = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}