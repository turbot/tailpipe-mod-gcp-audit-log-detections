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
    detection.iam_role_granted_to_all_users,
    detection.iam_service_account_deleted,
    detection.iam_service_account_disabled,
    detection.iam_service_account_key_created,
    detection.iam_workforce_pool_updated,
    detection.resourcemanager_owner_role_policy_set,
    detection.sql_ssl_certificate_deleted,
    detection.sql_user_deleted,
  ]

  tags = local.mitre_attack_v161_ta0003_t1098_common_tags
}
