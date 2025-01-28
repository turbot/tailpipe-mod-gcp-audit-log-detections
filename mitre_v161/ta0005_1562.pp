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
    detection.appengine_ingress_firewall_rule_created,
    detection.appengine_ingress_firewall_rule_deleted,
    detection.appengine_ingress_firewall_rule_updated,
    detection.artifact_registry_repository_deleted,
    detection.artifact_registry_package_deleted,
    detection.compute_disk_with_small_size,
  ]

  tags = local.mitre_v161_ta0005_t1562_common_tags
}
