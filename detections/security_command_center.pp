locals {
  security_command_center_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/SecurityCommandCenter"
  })
}

benchmark "security_command_center_detections" {
  title       = "Security Command Center Detections"
  description = "This benchmark contains recommendations when scanning audit logs for Security Command Center events."
  type        = "detection"
  children = [
    detection.security_command_center_notification_config_deleted
  ]

  tags = merge(local.security_command_center_common_tags, {
    type = "Benchmark"
  })
}

detection "security_command_center_notification_config_deleted" {
  title           = "Security Command Center Notification Config Deleted"
  description     = "Detect when a Security Command Center notification configuration was deleted to check for potential risks, such as disruption of security notifications or unauthorized changes that could hinder threat monitoring."
  documentation   = file("./detections/docs/security_command_center_notification_config_deleted.md")
  severity        = "high"
  query           = query.security_command_center_notification_config_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.security_command_center_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

query "security_command_center_notification_config_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.cloud.securitycenter.v%.securitycenter.deletenotificationconfig'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
