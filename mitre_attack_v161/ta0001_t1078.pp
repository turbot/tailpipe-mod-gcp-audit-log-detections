locals {
  mitre_attack_v161_ta0001_t1078_common_tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    mitre_technique_id = "T1078"
  })
}

benchmark "mitre_attack_v161_ta0001_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1078.md")
  children = [
    detection.iam_service_account_access_token_generated,
    detection.iam_service_account_deleted,
    detection.iam_service_account_disabled,
    detection.iam_service_account_key_created,
  ]

  tags = local.mitre_attack_v161_ta0001_t1078_common_tags
}
