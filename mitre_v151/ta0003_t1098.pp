locals {
  mitre_v151_ta0003_t1098_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1098"
  })
}

benchmark "mitre_v151_ta0003_t1098" {
  title         = "T1098 Account Manipulation"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0003_t1098.md")
  children = [
    detection.audit_log_admin_activity_detect_disabled_service_account,
    detection.audit_log_admin_activity_detect_iam_policy_granting_owner_role,
    detection.audit_log_admin_activity_detect_iam_roles_granting_access_to_all_authenticated_users,
    detection.audit_log_admin_activity_detect_iam_workforce_pool_update,
    detection.audit_log_admin_activity_detect_service_account_deletions,
    detection.audit_log_admin_activity_detect_service_account_key_creation,
  ]

  tags = local.mitre_v151_ta0003_t1098_common_tags
}
