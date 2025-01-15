locals {
  mitre_v161_ta0001_t1078_common_tags = merge(local.mitre_v161_ta0001_common_tags, {
    mitre_technique_id = "T1078"
  })
}

benchmark "mitre_v161_ta0001_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0001_t1078.md")
  children = [
    detection.audit_logs_detect_access_shared_resources,
    detection.audit_logs_detect_disabled_service_account,
    detection.audit_logs_detect_iam_policy_revoked,
    detection.audit_logs_detect_login_without_mfa,
    detection.audit_logs_detect_service_account_deletions,
    detection.audit_logs_detect_service_account_key_creation,
    detection.audit_logs_detect_workload_identity_pool_provider_creation,
    detection.audit_logs_detect_iam_service_account_access_token_generations,
  ]

  tags = local.mitre_v161_ta0001_t1078_common_tags
}
