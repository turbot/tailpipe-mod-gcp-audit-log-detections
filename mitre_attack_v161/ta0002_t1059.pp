locals {
  mitre_attack_v161_ta0002_t1059_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_attack_technique_id = "T1059"
  })
}

benchmark "mitre_attack_v161_ta0002_t1059" {
  title         = "T1059 Command and Scripting Interpreter"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0002_t1059.md")
  children = [
    detection.resourcemanager_script_execution_policy_set,
  ]

  tags = local.mitre_attack_v161_ta0002_t1059_common_tags
}
