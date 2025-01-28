locals {
  mitre_attack_v161_ta0005_t1211_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_technique_id = "T1211"
  })
}

benchmark "mitre_attack_v161_ta0005_t1211" {
  title         = "T1211 Exploitation for Defense Evasion"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1211.md")
  children = [
    detection.detect_api_monitoring_disabled,
    detection.detect_api_monitoring_policies_deleted,
    detection.compute_vpc_flow_logs_disabled,
    detection.detect_iam_policy_removing_logging_admin_roles,
    detection.logging_sink_deleted,
    detection.detect_org_policies_revoked,
    detection.detect_iam_policies_set_at_project_level,

  ]

  tags = local.mitre_attack_v161_ta0005_t1211_common_tags
}
