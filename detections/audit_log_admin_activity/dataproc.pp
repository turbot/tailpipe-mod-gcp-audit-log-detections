# locals {
#   audit_log_admin_activity_dataproc_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
#     service  = "Dataproc"
#   })

  
# }

# detection_benchmark "audit_log_admin_activity_dataproc_detections" {
#   title       = "Admin Activity Dataproc Logs Detections"
#   description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Dataproc Logs."
#   type        = "detection"
#   children = [
    
#   ]

#   tags = merge(local.audit_log_admin_activity_dataproc_detection_common_tags, {
#     type = "Benchmark"
#   })
# }
