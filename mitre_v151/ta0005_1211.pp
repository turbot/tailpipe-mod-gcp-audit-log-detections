locals {
  mitre_v151_ta0005_t1211_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1211"
  })
}

benchmark "mitre_v151_ta0005_t1211" {
  title         = "T1211 Exploitation for Defense Evasion"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0005_t1211.md")
  children = [
    detection.audit_log_admin_activity_detect_api_monitoring_disabled,
    detection.audit_log_admin_activity_detect_disable_compute_vpc_flow_logs,
    detection.audit_log_admin_activity_detect_disabled_security_command_center,
    detection.audit_log_admin_activity_detect_iam_policy_removing_logging_admin_role,
    detection.audit_log_admin_activity_detect_log_sink_deletion_updates,
    detection.audit_log_admin_activity_detect_org_policy_revoked,
    detection.audit_log_admin_activity_detect_project_level_iam_policy_change,
  ]

  tags = local.mitre_v151_ta0005_t1211_common_tags
}
