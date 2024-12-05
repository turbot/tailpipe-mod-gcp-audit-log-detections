locals {
  audit_log_admin_activity_dlp_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "DLP"
  })

  audit_log_admin_activity_detect_dlp_reidentify_content_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_dlp_detections" {
  title       = "Admin Activity DLP Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity DLP Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_dlp_reidentify_content,
  ]

  tags = merge(local.audit_log_admin_activity_dlp_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_dlp_reidentify_content" {
  title       = "Detect DLP Reidentify Content"
  description = "Detect reidentification of content that might expose sensitive information or violate data privacy regulations."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_dlp_reidentify_content

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
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
      and method_name like 'google.privacy.dlp.v%.DlpService.ReidentifyContent'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
