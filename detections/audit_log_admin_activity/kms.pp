# locals {
#   audit_log_admin_activity_kms_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
#     service  = "KMS"
#   })

  
# }

# benchmark "audit_log_admin_activity_kms_detections" {
#   title       = "Admin Activity KMS Logs Detections"
#   description = "This detection benchmark contains recommendations when scanning GCP Admin Activity KMS Logs."
#   type        = "detection"
#   children = [
    
#   ]

#   tags = merge(local.audit_log_admin_activity_kms_detection_common_tags, {
#     type = "Benchmark"
#   })
# }