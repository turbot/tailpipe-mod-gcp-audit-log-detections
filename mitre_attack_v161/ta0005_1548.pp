locals {
  mitre_attack_v161_ta0005_t1548_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_attack_technique_id = "T1548"
  })
}

benchmark "mitre_attack_v161_ta0005_t1548" {
  title         = "T1548 Abuse Elevation Control Mechanism"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1548.md")
  children = [
    detection.iam_role_with_high_privileges_created,
    detection.iam_federated_identity_provider_updated,
    detection.iam_role_granted_to_all_users,
    detection.iam_service_account_token_creator_role_assigned,
    detection.compute_vpc_network_shared_to_external_project,
    detection.iam_service_account_access_token_generated,
  ]

  tags = local.mitre_attack_v161_ta0005_t1548_common_tags
}
