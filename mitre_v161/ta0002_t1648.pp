locals {
  mitre_v161_ta0002_t1648_common_tags = merge(local.mitre_v161_ta0002_common_tags, {
    mitre_technique_id = "T1648"
  })
}

benchmark "mitre_v161_ta0002_t1648" {
  title         = "T1648 Serverless Execution"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0002_t1648.md")
  children = [
    detection.detect_appengine_admin_api_execution_enabled,
    detection.detect_cloudfunctions_operation_deletions,
    detection.detect_cloudfunctions_publicly_accessible,
  ]

  tags = local.mitre_v161_ta0002_t1648_common_tags
}
