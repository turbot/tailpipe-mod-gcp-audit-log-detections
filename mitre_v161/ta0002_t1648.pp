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
    detection.appengine_admin_api_enabled,
    detection.cloudfunctions_operations_deleted,
    detection.cloudfunctions_publicly_accessible,
  ]

  tags = local.mitre_v161_ta0002_t1648_common_tags
}
