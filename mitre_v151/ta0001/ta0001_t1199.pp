locals {
  mitre_v151_ta0001_t1199_common_tags = merge(local.mitre_v151_ta0001_common_tags, {
    mitre_technique_id = "T1199"
  })
}

benchmark "mitre_v151_ta0001_t1199" {
  title         = "T1199 Trusted Relationship"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0001_t1199.md")
  children = [
    detection.audit_log_admin_activity_detect_vpc_network_shared_to_external_project,
    detection.audit_log_admin_activity_detect_iam_roles_granting_access_to_all_authenticated_users
  ]

  tags = local.mitre_v151_ta0001_t1199_common_tags
}
