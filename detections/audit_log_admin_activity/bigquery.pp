
# locals {
#   audit_log_admin_activity_bigquery_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
#     service  = "BigQuery"
#   })

  
# }

# benchmark "audit_log_admin_activity_bigquery_detections" {
#   title       = "Admin Activity BigQuery Logs Detections"
#   description = "This detection benchmark contains recommendations when scanning GCP Admin Activity BigQuery Logs."
#   type        = "detection"
#   children = [
    
#   ]

#   tags = merge(local.audit_log_admin_activity_bigquery_detection_common_tags, {
#     type = "Benchmark"
#   })
# }
