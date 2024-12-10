locals {
  mitre_v151_ta0002_t1648_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1648"
  })
}

benchmark "mitre_v151_ta0002_t1648" {
  title         = "T1648 Serverless Execution"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0002_t1648.md")
  children = [
    
  ]

  tags = local.mitre_v151_ta0002_t1648_common_tags
}
