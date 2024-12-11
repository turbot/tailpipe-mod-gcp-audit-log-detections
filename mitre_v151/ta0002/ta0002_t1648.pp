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
    detection.audit_log_admin_activity_detect_appengine_admin_api_execution_enabled,
    detection.audit_log_admin_activity_detect_cloudfunctions_invoked_by_pubsub,
    detection.audit_log_admin_activity_detect_cloudfunctions_operation_delete,
    detection.audit_log_admin_activity_detect_cloudfunctions_invoked_by_job_scheduler,
    detection.audit_log_admin_activity_detect_cloudfunctions_publicly_accessible,
  ]

  tags = local.mitre_v151_ta0002_t1648_common_tags
}
