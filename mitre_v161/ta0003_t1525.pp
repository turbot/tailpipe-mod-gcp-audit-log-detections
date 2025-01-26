locals {
  mitre_v161_ta0003_t1525_common_tags = merge(local.mitre_v161_ta0002_common_tags, {
    mitre_technique_id = "T1525"
  })
}

benchmark "mitre_v161_ta0003_t1525" {
  title         = "T1525 Implant Internal Image"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0003_t1525.md")
  children = [
    detection.artifact_registry_artifacts_overwritten,
    detection.artifact_registry_publicly_accessible,
  ]

  tags = local.mitre_v161_ta0003_t1525_common_tags
}
