locals {
  mitre_attack_v161_ta0006_t1110_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_attack_technique_id = "T1110"
  })
}

benchmark "mitre_attack_v161_ta0006_t1110" {
  title         = "T1110 Brute Forces"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0006_t1110.md")
  children = [
    detection.iam_service_account_access_token_generation_failed,
    detection.iam_service_account_signblob_failed,
    detection.iam_single_account_login_failed,
    detection.sql_login_failed,
  ]

  tags = local.mitre_attack_v161_ta0006_t1110_common_tags
}
