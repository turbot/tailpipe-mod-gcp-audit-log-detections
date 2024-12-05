locals {
  audit_log_admin_activity_sql_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "SQL"
  })

  audit_log_admin_activity_detect_sql_database_changes_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

detection_benchmark "audit_log_admin_activity_sql_detections" {
  title       = "Admin Activity SQL Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity SQL Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_sql_database_changes,
  ]

  tags = merge(local.audit_log_admin_activity_sql_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_sql_database_changes" {
  title       = "Detect SQL Database Changes"
  description = "Detect changes to SQL databases that could signal unauthorized modifications or potential security risks."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_sql_database_changes

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_log_admin_activity_detect_sql_database_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_sql_database_changes_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'sqladmin.googleapis.com'
      and method_name in ('cloudsql.instances.delete', 'cloudsql.instances.patch')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
