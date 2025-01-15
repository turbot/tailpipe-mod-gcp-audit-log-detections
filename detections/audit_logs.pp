benchmark "audit_log_detections" {
  title       = "Audit Log Detections"
  description = "This detection benchmark contains recommendations when scanning Audit logs."
  type        = "detection"
  children = [
    benchmark.audit_logs_access_context_manager_detections,
    benchmark.audit_logs_apigateway_detections,
    benchmark.audit_logs_apigee_detections,
    benchmark.audit_logs_appengine_detections,
    benchmark.audit_logs_artifactregistry_detections,
    benchmark.audit_logs_cloudfunction_detections,
    benchmark.audit_logs_compute_detections,
    benchmark.audit_logs_dlp_detections,
    benchmark.audit_logs_dns_detections,
    benchmark.audit_logs_iam_detections,
    benchmark.audit_logs_kubernetes_detections,
    benchmark.audit_logs_logging_detections,
    benchmark.audit_logs_monitoring_detections,
    benchmark.audit_logs_resourcemanager_detections,
    benchmark.audit_logs_security_command_center_detections,
    benchmark.audit_logs_sql_detections,
    benchmark.audit_logs_storage_detections,
  ]

  tags = merge(local.gcp_audit_log_detections_common_tags, {
    type = "Benchmark"
  })
}
