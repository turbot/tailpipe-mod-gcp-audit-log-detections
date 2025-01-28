locals {
  mitre_attack_v161_ta0003_t1098_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_attack_technique_id = "T1098"
  })
}

benchmark "mitre_attack_v161_ta0003_t1098" {
  title         = "T1098 Account Manipulation"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1098.md")
  children = [
    detection.detect_cloudsql_ssl_certificate_deletions,
    detection.detect_disabled_service_accounts,
    detection.detect_iam_policies_granting_owner_roles,
    detection.detect_iam_roles_granting_access_to_all_authenticated_users,
    detection.detect_iam_workforce_pool_updates,
    detection.detect_service_account_deletions,
    detection.detect_service_account_key_creations,
    detection.detect_cloudsql_user_deletions,
  ]

  tags = local.mitre_attack_v161_ta0003_t1098_common_tags
}
