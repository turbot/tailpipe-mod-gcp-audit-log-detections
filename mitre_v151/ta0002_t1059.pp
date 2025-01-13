locals {
  mitre_v151_ta0002_t1059_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1059"
  })
}

benchmark "mitre_v151_ta0002_t1059" {
  title         = "T1059 Command and Scripting Interpreter"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0002_t1059.md")
  children = [
    detection.audit_logs_detect_iam_policy_to_enable_script_execution,
  ]

  tags = local.mitre_v151_ta0002_t1059_common_tags
}
