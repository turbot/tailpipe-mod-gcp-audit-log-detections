locals {
  mitre_v151_ta0003_t1136_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1136"
  })
}

benchmark "mitre_v151_ta0003_t1136" {
  title         = "T1136 Create Account"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0003_t1136.md")
  children = [
    detection.audit_log_admin_activity_detect_service_account_creation,
    detection.audit_log_admin_activity_detect_service_account_key_creation,
    detection.audit_log_admin_activity_detect_iam_policy_granting_owner_role,
    detection.audit_log_admin_activity_detect_iam_federated_identity_provider_creation,
    detection.audit_log_admin_activity_detect_iam_service_account_token_creator_role,
    detection.audit_log_admin_activity_detect_iam_policy_granting_apigateway_admin_role,
  ]

  tags = local.mitre_v151_ta0003_t1136_common_tags
}
