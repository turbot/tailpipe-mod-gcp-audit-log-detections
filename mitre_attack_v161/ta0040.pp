locals {
  mitre_attack_v161_ta0040_common_tags = merge(local.mitre_attack_v161_common_tags, {
    mitre_attack_tactic_id = "TA0040"
  })
}

benchmark "mitre_attack_v161_ta0040" {
  title         = "TA0040 Impact"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040.md")
  children = [
    benchmark.mitre_attack_v161_ta0040_t1491,
    benchmark.mitre_attack_v161_ta0040_t1531,
  ]

  tags = merge(local.mitre_attack_v161_ta0006_common_tags, {
    type = "Benchmark"
  })
}
