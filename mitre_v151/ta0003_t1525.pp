locals {
  mitre_v151_ta0003_t1525_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1525"
  })
}

benchmark "mitre_v151_ta0003_t1525" {
  title         = "T1525 Implant Internal Image"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0003_t1525.md")
  children = [
    detection.audit_log_admin_activity_detect_artifact_registry_overwritten,
    detection.audit_log_admin_activity_detect_artifact_registry_publicly_accessible,
  ]

  tags = local.mitre_v151_ta0003_t1525_common_tags
}
