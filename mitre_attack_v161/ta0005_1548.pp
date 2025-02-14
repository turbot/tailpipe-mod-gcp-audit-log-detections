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
    detection.iam_service_account_access_token_generated,
    detection.iam_service_account_token_creator_role_assigned,
  ]

  tags = local.mitre_attack_v161_ta0005_t1548_common_tags
}
