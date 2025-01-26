locals {
  mitre_v161_ta0006_t1110_common_tags = merge(local.mitre_v161_ta0002_common_tags, {
    mitre_technique_id = "T1110"
  })
}

benchmark "mitre_v161_ta0006_t1110" {
  title         = "T1110 Brute Forces"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0006_t1110.md")
  children = [
    detection.detect_cloudsql_login_failures,
    detection.detect_failed_iam_service_account_access_token_generations,
    detection.detect_service_account_signblob_failures,
    detection.detect_single_account_login_failures,
  ]

  tags = local.mitre_v161_ta0006_t1110_common_tags
}
