benchmark "audit_log_detections" {
  title       = "Audit Log Detections"
  description = "This detection benchmark contains recommendations when scanning Audit logs."
  type        = "detection"
  children = [
    benchmark.access_context_manager_detections,
    benchmark.apigateway_detections,
    benchmark.apigee_detections,
    benchmark.appengine_detections,
    benchmark.artifactregistry_detections,
    benchmark.cloudfunction_detections,
    benchmark.compute_detections,
    benchmark.dlp_detections,
    benchmark.dns_detections,
    benchmark.iam_detections,
    benchmark.kubernetes_detections,
    benchmark.logging_detections,
    benchmark.monitoring_detections,
    benchmark.resourcemanager_detections,
    benchmark.security_command_center_detections,
    benchmark.sql_detections,
    benchmark.storage_detections,
  ]

  tags = merge(local.gcp_audit_log_detections_common_tags, {
    type = "Benchmark"
  })
}
