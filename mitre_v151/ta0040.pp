locals {
  mitre_v151_ta0040_common_tags = merge(local.mitre_v151_common_tags, {
    mitre_tactic_id = "TA0040"
  })
}

benchmark "mitre_v151_ta0040" {
  title         = "TA0040 Impact"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040.md")
  children = [
    benchmark.mitre_v151_ta0040_t1491,
    benchmark.mitre_v151_ta0040_t1531,
  ]

  tags = merge(local.mitre_v151_ta0006_common_tags, {
    type = "Benchmark"
  })
}
