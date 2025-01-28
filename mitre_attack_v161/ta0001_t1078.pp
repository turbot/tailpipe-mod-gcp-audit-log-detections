locals {
  mitre_attack_v161_ta0001_t1078_common_tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    mitre_technique_id = "T1078"
  })
}

benchmark "mitre_attack_v161_ta0001_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1078.md")
  children = [
    detection.detect_access_shared_resources,
    detection.detect_disabled_service_accounts,
    detection.detect_iam_policies_revoked,
    detection.detect_logins_without_mfa,
    detection.detect_service_account_deletions,
    detection.detect_service_account_key_creations,
    detection.detect_workload_identity_pool_provider_creations,
    detection.detect_iam_service_account_access_token_generations,
  ]

  tags = local.mitre_attack_v161_ta0001_t1078_common_tags
}
