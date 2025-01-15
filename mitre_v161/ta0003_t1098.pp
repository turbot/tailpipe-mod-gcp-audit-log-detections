locals {
  mitre_v161_ta0003_t1098_common_tags = merge(local.mitre_v161_ta0002_common_tags, {
    mitre_technique_id = "T1098"
  })
}

benchmark "mitre_v161_ta0003_t1098" {
  title         = "T1098 Account Manipulation"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0003_t1098.md")
  children = [
    detection.detect_cloudsql_ssl_certificate_deletions,
    detection.detect_disabled_service_account,
    detection.detect_iam_policy_granting_owner_role,
    detection.detect_iam_roles_granting_access_to_all_authenticated_users,
    detection.detect_iam_workforce_pool_update,
    detection.detect_service_account_deletions,
    detection.detect_service_account_key_creation,
    detection.detect_cloudsql_user_deletions,
  ]

  tags = local.mitre_v161_ta0003_t1098_common_tags
}
