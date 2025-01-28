locals {
  mitre_attack_v161_ta0002_t1648_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_attack_technique_id = "T1648"
  })
}

benchmark "mitre_attack_v161_ta0002_t1648" {
  title         = "T1648 Serverless Execution"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0002_t1648.md")
  children = [
    detection.cloudfunction_deleted,
    detection.cloudfunction_publicly_accessible,
  ]

  tags = local.mitre_attack_v161_ta0002_t1648_common_tags
}
