locals {
  logging_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    folder  = "Logging"
    service = "GCP/Logging"
  })
}

benchmark "logging_detections" {
  title       = "Logging Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Logging events."
  type        = "detection"
  children = [
    detection.logging_bucket_deleted,
    detection.logging_sink_deleted,
  ]

  tags = merge(local.logging_common_tags, {
    type = "Benchmark"
  })
}

detection "logging_sink_deleted" {
  title           = "Logging Sink Deleted"
  description     = "Detect when a logging sink was deleted, potentially disrupting logging configurations or indicating unauthorized access attempts. Monitoring logging sink deletions helps ensure logging integrity and enables the timely identification of suspicious activities."
  documentation   = file("./detections/docs/logging_sink_deleted.md")
  severity        = "medium"
  query           = query.logging_sink_deleted
  display_columns = local.detection_display_columns

  tags = local.logging_common_tags
}

detection "logging_bucket_deleted" {
  title           = "Logging Bucket Deleted"
  description     = "Detect when a logging bucket was deleted, potentially disrupting logging configurations or indicating unauthorized access attempts. Monitoring logging bucket deletions helps maintain logging integrity and provides visibility into suspicious activities."
  documentation   = file("./detections/docs/logging_bucket_deleted.md")
  severity        = "medium"
  query           = query.logging_bucket_deleted
  display_columns = local.detection_display_columns

  tags = local.logging_common_tags
}

query "logging_sink_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.logging.v%.configservicev%.deletesink'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ

  tags = local.logging_common_tags
}

query "logging_bucket_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.logging.v%.configservicev%.deletebucket'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ

  tags = local.logging_common_tags
}