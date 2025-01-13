locals {
  mitre_v151_ta0005_t1078_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1078"
  })
}

benchmark "mitre_v151_ta0005_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0005_t1078.md")
  children = [
    benchmark.mitre_v151_ta0005_t1078_004
  ]

  tags = local.mitre_v151_ta0005_t1078_common_tags
}

benchmark "mitre_v151_ta0005_t1078_004" {
  title         = "T1078.004 Valid Accounts: Cloud Accounts"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0005_t1078_004.md")
  children = [
    detection.audit_logs_security_command_center_calculate_container_threat_detection_settings,
    detection.audit_logs_security_command_center_calculate_event_threat_detection_settings,
  ]
}