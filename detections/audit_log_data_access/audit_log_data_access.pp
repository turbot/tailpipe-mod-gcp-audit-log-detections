locals {
  audit_log_data_access_detection_common_tags = merge(local.gcp_detections_common_tags, {
    service = "GCP/AuditLogDataAccess"
  })

}

benchmark "audit_logs_data_access_detections" {
  title       = "Data Access Audit Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Data Access Audit Logs."
  type        = "detection"
  children = [
    benchmark.audit_logs_data_access_iam_detections,
    benchmark.audit_logs_data_access_security_command_center_detections,
    benchmark.audit_logs_data_access_sql_detections,
  ]

  tags = merge(local.audit_log_data_access_detection_common_tags, {
    type = "Benchmark"
  })
}
