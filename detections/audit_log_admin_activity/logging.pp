locals {
  audit_log_admin_activity_logging_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/Logging"
  })
  audit_log_admin_activity_detect_unauthorized_access_attempts_sql_columns    = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_log_sink_deletion_updates_sql_columns       = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_logging_bucket_deletion_updates_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_logging_detections" {
  title       = "Admin Activity Logging Logs Detections" // TODO: Should this be "Admin Activity Logging Detections"?
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Logging Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_unauthorized_access_attempts,
    detection.audit_log_admin_activity_detect_log_sink_deletion_updates,
    detection.audit_log_admin_activity_detect_logging_bucket_deletion_updates,
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
  title           = "Detect Log Sink Deletion Updates"
  description     = "Detect deletions of log sinks that might disrupt logging configurations or indicate unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_log_sink_deletion_updates
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_logging_bucket_deletion_updates" {
  title           = "Detect Logging Bucket Deletion Updates"
  description     = "Detect deletions of logging buckets that might disrupt logging configurations or indicate unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_logging_bucket_deletion_updates
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
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
      and method_name ilike 'google.logging.v%.configservicev%.deletesink'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_logging_bucket_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_logging_bucket_deletion_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'logging.googleapis.com'
      and method_name ilike 'google.logging.v%.configservicev%.deletebucket'
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
      method_name ilike 'google.logging.v%.writelogentries'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
