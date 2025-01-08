locals {
  mitre_v151_ta0005_t1548_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1548"
  })
}

benchmark "mitre_v151_ta0005_t1548" {
  title         = "T1548 Abuse Elevation Control Mechanism"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0005_t1548.md")
  children = [
    detection.audit_log_admin_activity_detect_high_privilege_iam_roles,
    detection.audit_log_admin_activity_detect_iam_federated_identity_provider_updation,
    detection.audit_log_admin_activity_detect_iam_roles_granting_access_to_all_authenticated_users,
    detection.audit_log_admin_activity_detect_iam_service_account_token_creator_role,
    audit_log_data_access_detect_service_account_access_token_generation,
    detection.audit_log_admin_activity_detect_vpc_network_shared_to_external_project,
  ]

  tags = local.mitre_v151_ta0005_t1548_common_tags
}
