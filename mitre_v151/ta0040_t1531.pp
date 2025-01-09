locals {
  mitre_v151_ta0040_t1531_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1531"
  })
}

benchmark "mitre_v151_ta0040_t1531" {
  title         = "T1531 Account Access Removal"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040_t1531.md")
  children = [
    detection.audit_logs_admin_activity_detect_cloudfunctions_function_code_modifications,
    detection.audit_logs_admin_activity_detect_service_account_key_deletions,
    detection.audit_logs_admin_activity_detect_iam_roles_permission_revocations
  ]

  tags = local.mitre_v151_ta0006_t1110_common_tags
}
