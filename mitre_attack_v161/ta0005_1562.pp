locals {
  mitre_attack_v161_ta0005_t1562_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_attack_technique_id = "T1525"
  })
}

benchmark "mitre_attack_v161_ta0005_t1562" {
  title         = "T1562 Impair Defenses"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1562.md")
  children = [
    detection.app_engine_firewall_ingress_rule_created,
    detection.app_engine_firewall_ingress_rule_deleted,
    detection.app_engine_firewall_ingress_rule_updated,
    detection.artifact_registry_package_deleted,
    detection.artifact_registry_repository_deleted,
  ]

  tags = local.mitre_attack_v161_ta0005_t1562_common_tags
}
