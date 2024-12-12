locals {
  audit_log_admin_activity_detection_common_tags = merge(local.gcp_detections_common_tags, {
    service = "GCP/AuditLogAdminActivity"
  })

}

benchmark "audit_log_admin_activity_detections" {
  title       = "Admin Activity Audit Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Audit Logs."
  type        = "detection"
  children = [
    benchmark.audit_log_admin_activity_access_context_manager_detections,
    benchmark.audit_log_admin_activity_appengine_detections,
    benchmark.audit_log_admin_activity_compute_detections,
    benchmark.audit_log_admin_activity_dlp_detections,
    benchmark.audit_log_admin_activity_dns_detections,
    benchmark.audit_log_admin_activity_iam_detections,
    benchmark.audit_log_admin_activity_kubernetes_detections,
    benchmark.audit_log_admin_activity_logging_detections,
    benchmark.audit_log_admin_activity_monitoring_detections,
    # benchmark.audit_log_admin_activity_pubsub_detections,
    benchmark.audit_log_admin_activity_resourcemanager_detections,
    # benchmark.audit_log_admin_activity_sql_detections,
    benchmark.audit_log_admin_activity_storage_detections,
    benchmark.audit_log_admin_activity_apigee_detections,
    benchmark.audit_log_admin_activity_cloudfunction_detections,
    benchmark.audit_log_admin_activity_apigateway_detections,
    benchmark.audit_log_admin_activity_artifactregistry_detections,
  ]

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    type = "Benchmark"
  })
}
