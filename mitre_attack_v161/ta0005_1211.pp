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
    detection.compute_vpc_flow_logs_disabled,
    detection.logging_sink_deleted,
    detection.monitoring_alert_policy_deleted,
    detection.monitoring_metric_descriptor_deleted,
    detection.resource_manager_iam_policy_set,
  ]

  tags = local.mitre_attack_v161_ta0005_t1211_common_tags
}
