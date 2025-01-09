locals {
  mitre_v151_ta0002_t1651_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1651"
  })
}

benchmark "mitre_v151_ta0002_t1651" {
  title         = "T1651 Cloud Administration Command"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0002_t1651.md")
  children = [
    detection.audit_log_admin_activity_detect_apigateway_configured_to_execute_backend_commands,
    detection.audit_log_admin_activity_detect_cloud_scheduler_run_job,
    detection.audit_log_admin_activity_detect_container_executed,
    detection.audit_log_data_access_detect_service_account_access_token_generation
  ]

  tags = local.mitre_v151_ta0002_t1651_common_tags
}
