locals {
  mitre_v151_ta0040_t1491_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1491"
  })
}

benchmark "mitre_v151_ta0040_t1491" {
  title         = "T1491 Defacement"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040_t1491.md")
  children = [
    detection.audit_log_admin_activity_detect_compute_instances_metadata_startup_script_modifications,
  ]

  tags = local.mitre_v151_ta0040_t1491_common_tags
}
