locals {
  audit_log_admin_activity_detection_common_tags = {
    service = "GCP/AuditLogs"
  }

}

detection_benchmark "audit_log_admin_activity_detections" {
  title       = "Admin Activity Audit Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Audit Logs."
  type        = "detection"
  children = [
    detection_benchmark.audit_log_admin_activity_access_context_manager_detections,
    detection_benchmark.audit_log_admin_activity_appengine_detections,
    detection_benchmark.audit_log_admin_activity_compute_detections,
    detection_benchmark.audit_log_admin_activity_dlp_detections,
    detection_benchmark.audit_log_admin_activity_dns_detections,
    detection_benchmark.audit_log_admin_activity_iam_detections,
    detection_benchmark.audit_log_admin_activity_kubernetes_detections,
    detection_benchmark.audit_log_admin_activity_logging_detections,
    detection_benchmark.audit_log_admin_activity_monitoring_detections,
    detection_benchmark.audit_log_admin_activity_pubsub_detections,
    detection_benchmark.audit_log_admin_activity_resourcemanager_detections,
    detection_benchmark.audit_log_admin_activity_sql_detections,
    detection_benchmark.audit_log_admin_activity_storage_detections,
  ]

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    type = "Benchmark"
  })
}
