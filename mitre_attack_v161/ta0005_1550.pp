locals {
  mitre_attack_v161_ta0005_t1550_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_attack_technique_id = "T1525"
  })
}

benchmark "mitre_attack_v161_ta0005_t1550" {
  title         = "T1550 Use Alternate Authentication Material"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1550.md")
  children = [
    detection.iam_service_account_access_token_generated,
  ]

  tags = local.mitre_attack_v161_ta0005_t1550_common_tags
}
