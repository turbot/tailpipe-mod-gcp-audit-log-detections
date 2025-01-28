locals {
  mitre_attack_v161_ta0003_t1136_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_technique_id = "T1136"
  })
}

benchmark "mitre_attack_v161_ta0003_t1136" {
  title         = "T1136 Create Account"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1136.md")
  children = [
    detection.detect_iam_federated_identity_provider_creations,
    detection.detect_iam_policy_granting_apigateway_admin_roles,
    detection.detect_iam_policies_granting_owner_roles,
    detection.detect_iam_service_account_token_creator_roles,
    detection.detect_service_account_creations,
    detection.detect_service_account_key_creations,
  ]

  tags = local.mitre_attack_v161_ta0003_t1136_common_tags
}
