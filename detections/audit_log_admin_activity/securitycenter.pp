locals {
  audit_log_admin_activity_securitycenter_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/SecurityCenter"
  })

  audit_log_admin_activity_detect_disable_security_command_center_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_logs_admin_activity_securitycenter_detections" {
  title       = "Security Center Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Security Center events."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_disable_security_command_center,
  ]

  tags = merge(local.audit_log_admin_activity_securitycenter_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_disable_security_command_center" {
  title           = "Detect Disable Security Command Center"
  description     = "Detect when the Security Command Center is disabled, which might disrupt security configurations or expose resources to threats."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_disable_security_command_center
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

query "audit_log_admin_activity_detect_disable_security_command_center" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_disable_security_command_center_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'securitycenter.googleapis.com'
      and method_name ilike 'google.cloud.securitycenter.v%.securitycenterservice.disable'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}