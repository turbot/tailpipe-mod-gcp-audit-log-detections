locals {
  audit_log_admin_activity_pubsub_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "Pub/Sub"
  })

  audit_log_admin_activity_detect_cloudfunctions_invoked_by_pubsub_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_pubsub_detections" {
  title       = "Admin Activity Pub/Sub Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Pubsub Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_cloudfunctions_invoked_by_pubsub
  ]

  tags = merge(local.audit_log_admin_activity_pubsub_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_cloudfunctions_invoked_by_pubsub" {
  title       = "Detect Cloud Functions Invoked by Pub/Sub"
  description = "Detect Cloud Functions invoked by Pub/Sub."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_cloudfunctions_invoked_by_pubsub

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0002:T1648"
  })
}

query "audit_log_admin_activity_detect_cloudfunctions_invoked_by_pubsub" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_cloudfunctions_invoked_by_pubsub_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudfunctions.googleapis.com'
      and method_name ilike 'google.cloud.functions.v%.CloudFunctionsService.CallFunction'
      and cast(request_metadata->'caller_supplied_user_agent' as varchar) = 'Google-PubSub'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
