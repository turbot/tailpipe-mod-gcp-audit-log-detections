locals {
  mitre_attack_v161_ta0001_t1199_common_tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    mitre_technique_id = "T1199"
  })
}

benchmark "mitre_attack_v161_ta0001_t1199" {
  title         = "T1199 Trusted Relationship"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1199.md")
  children = [
    detection.cloudfunctions_publicly_accessible,
    detection.detect_iam_roles_granting_access_to_all_authenticated_users,
    detection.detect_iam_service_account_token_creator_roles,
    detection.detect_organization_iam_policy_changes,
    detection.compute_vpc_network_shared_to_external_project,
  ]

  tags = local.mitre_attack_v161_ta0001_t1199_common_tags
}
