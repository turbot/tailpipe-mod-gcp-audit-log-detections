locals {
  audit_log_data_access_detection_common_tags = merge(local.gcp_detections_common_tags, {
    service = "GCP/AuditLogDataAccess"
  })

}

benchmark "audit_logs_data_access_detections" {
  title       = "Audit Log Data Access Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Data Access Audit Logs."
  type        = "detection"
  children = [
    benchmark.audit_log_data_access_security_command_center_detections,
  ]

  tags = merge(local.audit_log_data_access_detection_common_tags, {
    type = "Benchmark"
  })
}
