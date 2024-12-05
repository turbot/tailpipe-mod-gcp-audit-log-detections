# locals {
#   audit_log_admin_activity_cloudfunction_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
#     service  = "CloudFunctions"
#   })

  
# }

# detection_benchmark "audit_log_admin_activity_cloudfunction_detections" {
#   title       = "Admin Activity Cloudfunction Logs Detections"
#   description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Cloudfunction Logs."
#   type        = "detection"
#   children = [
    
#   ]

#   tags = merge(local.audit_log_admin_activity_cloudfunction_detection_common_tags, {
#     type = "Benchmark"
#   })
# }
