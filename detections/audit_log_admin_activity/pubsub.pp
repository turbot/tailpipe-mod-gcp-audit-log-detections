# locals {
#   audit_log_admin_activity_pubsub_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
#     service = "Pub/Sub"
#   })

# }

# benchmark "audit_log_admin_activity_pubsub_detections" {
#   title       = "Admin Activity Pub/Sub Logs Detections"
#   description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Pubsub Logs."
#   type        = "detection"
#   children = [
    
#   ]

#   tags = merge(local.audit_log_admin_activity_pubsub_detection_common_tags, {
#     type = "Benchmark"
#   })
# }
