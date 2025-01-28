locals {
  security_command_center_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/SecurityCommandCenter"
  })

  security_command_center_delete_notification_configs_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")

}

benchmark "security_command_center_detections" {
  title       = "Security Command Center Detections"
  description = "This benchmark contains recommendations when scanning audit logs for Security Center events."
  type        = "detection"
  children = [
    detection.security_command_center_delete_notification_configs
  ]

  tags = merge(local.security_command_center_common_tags, {
    type = "Benchmark"
  })
}

detection "security_command_center_delete_notification_configs" {
  title           = "Detect Security Command Center Delete Notification Configs"
  description     = "Detect deletions of Security Command Center notification configurations that might disrupt security configurations or expose resources to threats."
  documentation   = file("./detections/docs/security_command_center_delete_notification_configs.md")
  severity        = "high"
  query           = query.security_command_center_delete_notification_configs
  display_columns = local.detection_display_columns

  tags = merge(local.security_command_center_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

query "security_command_center_delete_notification_configs" {
  sql = <<-EOQ
    select
      ${local.security_command_center_delete_notification_configs_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'securitycenter.googleapis.com'
      and method_name ilike 'google.cloud.securitycenter.v%.securitycenter.deletenotificationconfig'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
