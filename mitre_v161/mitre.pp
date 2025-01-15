locals {
  mitre_v161_common_tags = merge(local.gcp_detections_common_tags, {
    mitre         = "true"
    mitre_version = "v16.1"
  })
}

// TODO: Should this be mitre_attack_v161?
benchmark "mitre_v161" {
  title         = "MITRE ATT&CK v16.1"
  description   = "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations."
  type          = "detection"
  documentation = file("./mitre_v161/docs/mitre.md")
  children = [
    benchmark.mitre_v161_ta0001,
    benchmark.mitre_v161_ta0002,
    benchmark.mitre_v161_ta0003,
    benchmark.mitre_v161_ta0004,
    benchmark.mitre_v161_ta0005,
    benchmark.mitre_v161_ta0006,
    benchmark.mitre_v161_ta0040,
  ]

  tags = merge(local.mitre_v161_common_tags, {
    type = "Benchmark"
  })
}
