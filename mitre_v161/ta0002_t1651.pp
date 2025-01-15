locals {
  mitre_v161_ta0002_t1651_common_tags = merge(local.mitre_v161_ta0002_common_tags, {
    mitre_technique_id = "T1651"
  })
}

benchmark "mitre_v161_ta0002_t1651" {
  title         = "T1651 Cloud Administration Command"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0002_t1651.md")
  children = [
    detection.audit_logs_detect_apigateway_configured_to_execute_backend_commands,
    detection.audit_logs_detect_cloud_scheduler_run_job,
    detection.audit_logs_detect_container_executed,
    detection.audit_logs_detect_iam_service_account_access_token_generations
  ]

  tags = local.mitre_v161_ta0002_t1651_common_tags
}
