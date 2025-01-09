locals {
  mitre_v151_ta0001_t1078_common_tags = merge(local.mitre_v151_ta0001_common_tags, {
    mitre_technique_id = "T1078"
  })
}

benchmark "mitre_v151_ta0001_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0001_t1078.md")
  children = [
    detection.audit_log_admin_activity_detect_access_shared_resources,
    detection.audit_log_admin_activity_detect_disabled_service_account,
    detection.audit_log_admin_activity_detect_iam_policy_revoked,
    detection.audit_log_admin_activity_detect_login_without_mfa,
    detection.audit_log_admin_activity_detect_service_account_deletions,
    detection.audit_log_admin_activity_detect_service_account_key_creation,
    detection.audit_log_admin_activity_detect_workload_identity_pool_provider_creation,
    detection.audit_log_data_access_detect_service_account_access_token_generation,
  ]

  tags = local.mitre_v151_ta0001_t1078_common_tags
}
