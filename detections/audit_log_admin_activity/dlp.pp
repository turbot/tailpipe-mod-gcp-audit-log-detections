locals {
  audit_log_admin_activity_dlp_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/DLP"
  })

  audit_log_admin_activity_detect_dlp_reidentify_content_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_logs_admin_activity_dlp_detections" {
  title       = "DLP Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for DLP events."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_dlp_reidentify_content,
  ]

  tags = merge(local.audit_log_admin_activity_dlp_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_dlp_reidentify_content" {
  title           = "Detect DLP Reidentify Contents"
  description     = "Detect reidentifications of content that could expose sensitive information or violate data privacy regulations, ensuring compliance and protecting against unauthorized data exposure."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_dlp_reidentify_content
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0009:T1119"
  })
}

query "audit_log_admin_activity_detect_dlp_reidentify_content" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_dlp_reidentify_content_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'dlp.googleapis.com'
      and method_name ilike 'google.privacy.dlp.v%.dlpservice.reidentifycontent'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
