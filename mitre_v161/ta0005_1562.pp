locals {
  mitre_v161_ta0005_t1562_common_tags = merge(local.mitre_v161_ta0002_common_tags, {
    mitre_technique_id = "T1525"
  })
}

benchmark "mitre_v161_ta0005_t1562" {
  title         = "T1562 Impair Defenses"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0005_t1562.md")
  children = [
    detection.detect_appengine_ingress_firewall_rule_creations,
    detection.detect_appengine_ingress_firewall_rule_deletions,
    detection.detect_appengine_ingress_firewall_rule_modifications,
    detection.detect_artifact_registry_package_deletion,
    detection.detect_artifact_registry_repository_deletion,
    detection.detect_artifact_registry_with_no_layers,
    detection.detect_compute_disk_size_small,
    detection.detect_encrypted_container_image_pushed,
  ]

  tags = local.mitre_v161_ta0005_t1562_common_tags
}
