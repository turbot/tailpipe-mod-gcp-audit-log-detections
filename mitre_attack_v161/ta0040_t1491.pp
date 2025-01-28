locals {
  mitre_attack_v161_ta0040_t1491_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_technique_id = "T1491"
  })
}

benchmark "mitre_attack_v161_ta0040_t1491" {
  title         = "T1491 Defacement"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1491.md")
  children = [
    
  ]

  tags = local.mitre_attack_v161_ta0040_t1491_common_tags
}
