# locals {
#   audit_log_admin_activity_sql_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
#     service = "SQL"
#   })

  
# }

# benchmark "audit_log_admin_activity_sql_detections" {
#   title       = "Admin Activity SQL Logs Detections"
#   description = "This detection benchmark contains recommendations when scanning GCP Admin Activity SQL Logs."
#   type        = "detection"
#   children = [
    
#   ]

#   tags = merge(local.audit_log_admin_activity_sql_detection_common_tags, {
#     type = "Benchmark"
#   })
# }

