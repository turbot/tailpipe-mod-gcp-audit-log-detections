locals {
  logging_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/Logging"
  })
  detect_unauthorized_access_attempts_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_log_sink_deletion_updates_sql_columns    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_logging_bucket_deletions_sql_columns     = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "logging_detections" {
  title       = "Logging Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Logging events."
  type        = "detection"
  children = [
    detection.detect_unauthorized_access_attempts,
    detection.detect_log_sink_deletion_updates,
    detection.detect_logging_bucket_deletions,
  ]

  tags = merge(local.logging_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_unauthorized_access_attempts" {
  title           = "Detect Unauthorized Access Attempts"
  description     = "Detect failed or unauthorized access attempts to GCP resources, ensuring prompt identification of potential security threats and mitigation actions."
  severity        = "high"
  query           = query.detect_unauthorized_access_attempts
  display_columns = local.detection_display_columns

  tags = merge(local.logging_common_tags, {
    mitre_attack_ids = "TA0006:T1078"
  })
}

detection "detect_log_sink_deletion_updates" {
  title           = "Detect Log Sink Deletions"
  description     = "Detect deletions of log sinks that might disrupt logging configurations or indicate unauthorized access attempts."
  severity        = "high"
  query           = query.detect_log_sink_deletion_updates
  display_columns = local.detection_display_columns

  tags = merge(local.logging_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

detection "detect_logging_bucket_deletions" {
  title           = "Detect Logging Bucket Deletions"
  description     = "Detect deletions of logging buckets that might disrupt logging configurations or indicate unauthorized access attempts."
  severity        = "high"
  query           = query.detect_logging_bucket_deletions
  display_columns = local.detection_display_columns

  tags = merge(local.logging_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "detect_log_sink_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.detect_log_sink_deletion_updates_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'logging.googleapis.com'
      and method_name ilike 'google.logging.v%.configserviceV%.deletesink'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_logging_bucket_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_logging_bucket_deletions_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'logging.googleapis.com'
      and method_name ilike 'google.logging.v%.configserviceV%.deletebucket'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_unauthorized_access_attempts" {
  sql = <<-EOQ
    select
      ${local.detect_unauthorized_access_attempts_sql_columns}
    from
      gcp_audit_log
    where
      method_name ilike 'google.logging.v%.loggingserviceV%.writelogentriesrequest'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
