locals {
  audit_log_admin_activity_logging_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/Logging"
  })
  audit_log_admin_activity_detect_unauthorized_access_attempts_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_log_sink_deletion_updates_sql_columns    = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_logging_bucket_deletions_sql_columns     = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_logs_admin_activity_logging_detections" {
  title       = "Logging Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Logging events."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_unauthorized_access_attempts,
    detection.audit_log_admin_activity_detect_log_sink_deletion_updates,
    detection.audit_log_admin_activity_detect_logging_bucket_deletions,
  ]

  tags = merge(local.audit_log_admin_activity_logging_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_unauthorized_access_attempts" {
  title           = "Detect Unauthorized Access Attempts"
  description     = "Detect failed or unauthorized access attempts to GCP resources, ensuring prompt identification of potential security threats and mitigation actions."
  severity        = "high"
  query           = query.audit_log_admin_activity_detect_unauthorized_access_attempts
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1078"
  })
}

detection "audit_log_admin_activity_detect_log_sink_deletion_updates" {
  title           = "Detect Log Sink Deletions"
  description     = "Detect deletions of log sinks that might disrupt logging configurations or indicate unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_log_sink_deletion_updates
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

detection "audit_log_admin_activity_detect_logging_bucket_deletions" {
  title           = "Detect Logging Bucket Deletions"
  description     = "Detect deletions of logging buckets that might disrupt logging configurations or indicate unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_logging_bucket_deletions
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "audit_log_admin_activity_detect_log_sink_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_log_sink_deletion_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'logging.googleapis.com'
      and method_name ilike 'google.logging.v%.configserviceV%.deletesink'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_logging_bucket_deletions" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_logging_bucket_deletions_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'logging.googleapis.com'
      and method_name ilike 'google.logging.v%.configserviceV%.deletebucket'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_unauthorized_access_attempts" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_unauthorized_access_attempts_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      method_name ilike 'google.logging.v%.loggingserviceV%.writelogentriesrequest'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
