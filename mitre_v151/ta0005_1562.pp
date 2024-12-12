locals {
  mitre_v151_ta0005_t1562_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1525"
  })
}

benchmark "mitre_v151_ta0005_t1562" {
  title         = "T1525 Impair Defenses"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0005_t1562.md")
  children = [
    detection.audit_log_admin_activity_detect_artifact_registry_with_no_layers,
    detection.audit_log_admin_activity_detect_compute_image_logging_disabled,
    detection.audit_log_admin_activity_detect_compute_disk_size_small,
    detection.audit_log_admin_activity_detect_encrypted_container_image_pushed,
    detection.audit_log_admin_activity_detect_artifact_registry_artifact_deletion,
    detection.audit_log_admin_activity_detect_compute_image_os_login_disabled,
  ]

  tags = local.mitre_v151_ta0005_t1562_common_tags
}
