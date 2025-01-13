locals {
  audit_log_sql_detection_common_tags = merge(local.audit_logs_detection_common_tags, {
    service = "GCP/SQL"
  })
  audit_logs_detect_cloudsql_ssl_certificate_deletions_sql_columns = replace(local.audit_logs_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_logs_detect_cloudsql_login_failures_sql_columns            = replace(local.audit_logs_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_logs_detect_cloudsql_user_deletions_sql_columns            = replace(local.audit_logs_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_logs_sql_detections" {
  title       = "SQL Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for SQL events."
  type        = "detection"
  children = [
    detection.audit_logs_detect_cloudsql_ssl_certificate_deletions,
    detection.audit_logs_detect_cloudsql_login_failures,
    detection.audit_logs_detect_cloudsql_user_deletions,
  ]

  tags = merge(local.audit_log_sql_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_logs_detect_cloudsql_ssl_certificate_deletions" {
  title           = "Detect Cloud SQL SSL Certificate Deletions"
  description     = "Detect Cloud SQL SSL certificate deletions that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_logs_detect_cloudsql_ssl_certificate_deletions
  display_columns = local.audit_logs_detection_display_columns

  tags = merge(local.audit_logs_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

detection "audit_logs_detect_cloudsql_login_failures" {
  title           = "Detect Cloud SQL Login Failures"
  description     = "Detect failed login attempts to Cloud SQL instances. Multiple failed logins may indicate unauthorized access attempts, misconfigured applications, or potential brute force attacks targeting database instances. This detection helps identify potential security threats to database resources."
  severity        = "medium"
  query           = query.audit_logs_detect_cloudsql_login_failures
  display_columns = local.audit_logs_detection_display_columns

  tags = merge(local.audit_logs_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

detection "audit_logs_detect_cloudsql_user_deletions" {
  title           = "Detect Cloud SQL User Deletions"
  description     = "Detect successful deletion of users from Cloud SQL instances. This detection helps track changes to database access controls, ensuring compliance with security policies and helping identify potential account tampering or privilege removal attacks."
  severity        = "medium"
  query           = query.audit_logs_detect_cloudsql_user_deletions
  display_columns = local.audit_logs_detection_display_columns

  tags = merge(local.audit_logs_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "audit_logs_detect_cloudsql_login_failures" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_cloudsql_login_failures_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'sqladmin.googleapis.com'
      and method_name ilike 'cloudsql.instances.login'
      and status.code = 7
    order by
      timestamp desc;
  EOQ
}

query "audit_logs_detect_cloudsql_user_deletions" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_cloudsql_user_deletions_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'sqladmin.googleapis.com'
      and method_name ilike 'cloudsql.users.delete'
      ${local.audit_log_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_logs_detect_cloudsql_ssl_certificate_deletions" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_cloudsql_ssl_certificate_deletions_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'sqladmin.googleapis.com'
      and method_name ilike 'cloudsql.sslCerts.delete'
      ${local.audit_log_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
