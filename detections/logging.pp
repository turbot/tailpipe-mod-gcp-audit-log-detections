locals {
  logging_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
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
    detection.logging_unauthorized_access_attempt,
  ]

  tags = merge(local.logging_common_tags, {
    type = "Benchmark"
  })
}

detection "logging_unauthorized_access_attempt" {
  title           = "Logging Unauthorized Access Attempt"
  description     = "Detect unauthorized access attempts to GCP resources, ensuring prompt identification of potential security threats and mitigation actions."
  documentation   = file("./detections/docs/logging_unauthorized_access_attempt.md")
  severity        = "high"
  query           = query.logging_unauthorized_access_attempt
  display_columns = local.detection_display_columns

  tags = merge(local.logging_common_tags, {
    mitre_attack_ids = "TA0006:T1078"
  })
}

detection "logging_sink_deleted" {
  title           = "Logging Sink Deleted"
  description     = "Detect deletions of log sinks that might disrupt logging configurations or indicate unauthorized access attempts."
  documentation   = file("./detections/docs/logging_sink_deleted.md")
  severity        = "high"
  query           = query.logging_sink_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.logging_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

detection "logging_bucket_deleted" {
  title           = "Logging Bucket Deleted"
  description     = "Detect deletions of logging buckets that might disrupt logging configurations or indicate unauthorized access attempts."
  documentation   = file("./detections/docs/logging_bucket_deleted.md")
  severity        = "high"
  query           = query.logging_bucket_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.logging_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "logging_unauthorized_access_attempt" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.logging.v%.loggingserviceV%.writelogentriesrequest'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "logging_sink_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      service_name = 'logging.googleapis.com'
      and method_name ilike 'google.logging.v%.configservicev%.deletesink'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "logging_bucket_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      service_name = 'logging.googleapis.com'
      and method_name ilike 'google.logging.v%.configservicev%.deletebucket'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}