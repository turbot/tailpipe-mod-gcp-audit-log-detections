locals {
  mitre_v151_ta0006_t1552_common_tags = merge(local.mitre_v151_common_tags, {
    mitre_tactic_id = "t1552"
  })
}

benchmark "mitre_v151_ta0006_t1552" {
  title         = "TA0006 Credentials from Password Stores"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0006_t1552.md")
  children = [
    detection.audit_log_admin_activity_detect_unexpected_key_rotations,
  ]

  tags = merge(local.mitre_v151_ta0006_t1552_common_tags, {
    type = "Benchmark"
  })
}
