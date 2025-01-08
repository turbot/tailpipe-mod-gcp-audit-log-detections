locals {
  mitre_v151_ta0006_t1110_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1110"
  })
}

benchmark "mitre_v151_ta0006_t1110" {
  title         = "T1110 Brute Forces"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0006_t1110.md")
  children = [
    detection.audit_log_data_access_detect_cloudsql_login_failure,
    detection.audit_log_data_access_detect_failed_service_account_access_token_generation,
    detection.audit_log_data_access_detect_service_account_signblob_failure,
    detection.audit_log_data_access_detect_single_account_login_failure,
  ]

  tags = local.mitre_v151_ta0006_t1110_common_tags
}
