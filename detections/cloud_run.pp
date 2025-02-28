locals {
  cloud_run_function_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    folder  = "Cloud Run Function"
    service = "GCP/CloudRunFunction"
  })
}

benchmark "cloud_run_detections" {
  title       = "Cloud Run Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Cloud Run Function events."
  type        = "detection"
  children = [
    detection.cloud_run_function_deleted,
  ]

  tags = merge(local.cloud_run_function_common_tags, {
    type = "Benchmark"
  })
}

detection "cloud_run_function_deleted" {
  title           = "Cloud Run Function Deleted"
  description     = "Detect when a Cloud Run Function was deleted to check for potential accidental loss of critical serverless resources or unauthorized deletions."
  documentation   = file("./detections/docs/cloud_run_function_deleted.md")
  severity        = "medium"
  query           = query.cloud_run_function_deleted
  display_columns = local.detection_display_columns

  tags = local.cloud_run_function_common_tags
}

query "cloud_run_function_deleted" {
  sql = <<-EOQ
    select 
      ${local.detection_sql_resource_column_resource_name}
    from 
      gcp_audit_log
    where
      method_name ilike 'google.cloud.functions.v%.functionservice.deletefunction'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ

  tags = local.cloud_run_function_common_tags
}