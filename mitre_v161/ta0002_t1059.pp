locals {
  mitre_v161_ta0002_t1059_common_tags = merge(local.mitre_v161_ta0002_common_tags, {
    mitre_technique_id = "T1059"
  })
}

benchmark "mitre_v161_ta0002_t1059" {
  title         = "T1059 Command and Scripting Interpreter"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0002_t1059.md")
  children = [
    detection.detect_iam_policies_enabling_script_execution,
  ]

  tags = local.mitre_v161_ta0002_t1059_common_tags
}
