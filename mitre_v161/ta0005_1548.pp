locals {
  mitre_v161_ta0005_t1548_common_tags = merge(local.mitre_v161_ta0002_common_tags, {
    mitre_technique_id = "T1548"
  })
}

benchmark "mitre_v161_ta0005_t1548" {
  title         = "T1548 Abuse Elevation Control Mechanism"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0005_t1548.md")
  children = [
    detection.detect_high_privilege_iam_roles,
    detection.detect_iam_federated_identity_provider_updations,
    detection.detect_iam_roles_granting_access_to_all_authenticated_users,
    detection.detect_iam_service_account_token_creator_roles,
    detection.compute_vpc_network_shared_to_external_project,
    detection.detect_iam_service_account_access_token_generations,
  ]

  tags = local.mitre_v161_ta0005_t1548_common_tags
}
