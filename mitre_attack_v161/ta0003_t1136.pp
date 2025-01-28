locals {
  mitre_attack_v161_ta0003_t1136_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_attack_technique_id = "T1136"
  })
}

benchmark "mitre_attack_v161_ta0003_t1136" {
  title         = "T1136 Create Account"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1136.md")
  children = [
    detection.iam_federated_identity_provider_created,
    detection.iam_policy_granted_apigateway_admin_role,
    detection.resourcemanager_owner_role_policy_set,
    detection.iam_service_account_token_creator_role_assigned,
    detection.iam_service_account_created,
    detection.iam_service_account_key_created,
  ]

  tags = local.mitre_attack_v161_ta0003_t1136_common_tags
}
