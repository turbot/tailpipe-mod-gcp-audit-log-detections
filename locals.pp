// Benchmarks and controls for specific services should override the "service" tag
locals {
  gcp_detections_common_tags = {
    category = "Detection"
    plugin   = "gcp"
    service  = "GCP"
  }
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  audit_log_detection_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  string_split(method_name, '.')[1] || ':' || method_name as operation,
  __RESOURCE_SQL__ as resource,
  authentication_principal as actor,
  tp_source_ip as source_ip,
  tp_index::varchar as project,
  tp_id as source_id,
  *
  EOQ

  // Keep same order as SQL statement for easier readability
  # cloudtrail_log_detection_default_columns = [
  #   "timestamp",
  #   "operation",
  #   "resource",
  #   "actor",
  #   "source_ip",
  #   "account_id",
  #   "region",
  #   "source_id"
  # ]
}
