locals {
  audit_log_admin_activity_keymanagement_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/Key Management"
  })
  audit_log_admin_activity_detect_key_rotation_set_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_logs_admin_activity_keymanagement_detections" {
  title       = "Key Managements Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Key Management events."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_unexpected_key_rotations,
  ]

  tags = merge(local.audit_log_admin_activity_keymanagement_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_unexpected_key_rotations" {
  title           = "Detect Rotation of Keys"
  description     = "Detect unexpected rotation of keys, which could be an attempt to hide unauthorized access."
  severity        = "high"
  query           = query.audit_log_admin_activity_detect_unexpected_key_rotations
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_keymanagement_detection_common_tags, {
    mitre_attack_ids = "TA0006:t1552"
  })
}

query "audit_log_admin_activity_detect_unexpected_key_rotations" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_key_rotation_set_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudkms.googleapis.com'
      and method_name ilike 'UpdateCryptoKeyPrimaryVersion'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
