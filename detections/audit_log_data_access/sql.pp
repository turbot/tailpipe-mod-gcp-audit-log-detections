locals {
  audit_log_data_access_sql_detection_common_tags = merge(local.audit_log_data_access_detection_common_tags, {
    service = "GCP/SQL"
  })
  audit_log_data_access_detect_cloudsql_login_failure_sql_columns = replace(local.audit_log_data_access_detection_sql_columns, "__RESOURCE_sql__", "resource_name")
}

benchmark "audit_log_data_access_sql_detections" {
  title       = "SQL Detections"
  description = "This benchmark contains recommendations when scanning Data Acess audit logs for SQL events."
  type        = "detection"
  children = [
    detection.audit_log_data_access_detect_cloudsql_login_failure
  ]

  tags = merge(local.audit_log_data_access_sql_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_data_access_detect_cloudsql_login_failure" {
  title           = "Detect Failed Cloud SQL Instance Login Attempts"
  description     = "Detect failed login attempts to Cloud SQL instances. Multiple failed logins may indicate unauthorized access attempts, misconfigured applications, or potential brute force attacks targeting database instances. This detection helps identify potential security threats to database resources."
  severity        = "medium"
  query           = query.audit_log_data_access_detect_cloudsql_login_failure
  display_columns = local.audit_log_data_access_detection_display_columns

  tags = merge(local.audit_log_data_access_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

detection "audit_log_data_access_detect_cloudsql_user_deletion" {
  title           = "Detect Cloud SQL User Deletion"
  description     = "Detect successful deletion of users from Cloud SQL instances. This detection helps track changes to database access controls, ensuring compliance with security policies and helping identify potential account tampering or privilege removal attacks."
  severity        = "medium"
  query           = query.audit_log_data_access_detect_cloudsql_user_deletion
  display_columns = local.audit_log_data_access_detection_display_columns

  tags = merge(local.audit_log_data_access_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "audit_log_data_access_detect_cloudsql_login_failure" {
  sql = <<-EOQ
    select
      ${local.audit_log_data_access_detect_cloudsql_login_failure_sql_columns}
    from
      gcp_audit_log_data_access
    where
      service_name = 'sqladmin.googleapis.com'
      and method_name ilike 'cloudsql.instances.login'
      and status.code = 7
    order by
      timestamp desc;
  EOQ
}

query "audit_log_data_access_detect_cloudsql_user_deletion" {
  sql = <<-EOQ
    select
      ${local.audit_log_data_access_detect_cloudsql_user_deletion_sql_columns}
    from
      gcp_audit_log_data_access
    where
      service_name = 'sqladmin.googleapis.com'
      and method_name ilike 'cloudsql.users.delete'
      ${local.audit_log_data_access_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
