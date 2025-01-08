locals {
  audit_log_admin_activity_sql_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/SQL"
  })
  audit_log_admin_activity_detect_cloudsql_ssl_certificate_deletions_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_sql_detections" {
  title       = "SQL Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for SQL events."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_cloudsql_ssl_certificate_deletions
  ]

  tags = merge(local.audit_log_admin_activity_sql_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_cloudsql_ssl_certificate_deletions" {
  title           = "Detect Cloud SQL User Deletion"
  description     = "Detect successful deletion of users from Cloud SQL instances. This detection helps track changes to database access controls, ensuring compliance with security policies and helping identify potential account tampering or privilege removal attacks."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_cloudsql_ssl_certificate_deletions
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "audit_log_admin_activity_detect_cloudsql_ssl_certificate_deletions" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_cloudsql_ssl_certificate_deletions_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'sqladmin.googleapis.com'
      and method_name ilike 'cloudsql.sslCerts.delete'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
