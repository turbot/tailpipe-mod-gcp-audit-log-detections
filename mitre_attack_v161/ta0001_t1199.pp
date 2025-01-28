locals {
  mitre_attack_v161_ta0001_t1199_common_tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    mitre_attack_technique_id = "T1199"
  })
}

benchmark "mitre_attack_v161_ta0001_t1199" {
  title         = "T1199 Trusted Relationship"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1199.md")
  children = [
    detection.cloudfunctions_publicly_accessible,
    detection.compute_vpc_network_shared_to_external_project,
    detection.iam_organization_policy_updated,
    detection.iam_role_granted_to_all_users,
    detection.iam_service_account_token_creator_role_assigned,
  ]

  tags = local.mitre_attack_v161_ta0001_t1199_common_tags
}
