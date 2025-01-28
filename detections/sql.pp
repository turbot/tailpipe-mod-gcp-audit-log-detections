locals {
  sql_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/SQL"
  })
  sql_ssl_certificate_deleted_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  sql_login_failed_sql_columns            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  sql_user_deleted_sql_columns            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "sql_detections" {
  title       = "SQL Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for SQL events."
  type        = "detection"
  children = [
    detection.sql_login_failed,
    detection.sql_ssl_certificate_deleted,
    detection.sql_user_deleted,
  ]

  tags = merge(local.sql_common_tags, {
    type = "Benchmark"
  })
}

detection "sql_ssl_certificate_deleted" {
  title           = "SQL SSL Certificate Deleted"
  description     = "Detect SQL SSL certificate deletions that might expose resources to threats or signal unauthorized access attempts."
  documentation   = file("./detections/docs/sql_ssl_certificate_deleted.md")
  severity        = "medium"
  query           = query.sql_ssl_certificate_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

detection "sql_login_failed" {
  title           = "SQL Login Failed"
  description     = "Detect failed login attempts to SQL instances. Multiple failed logins may indicate unauthorized access attempts, misconfigured applications, or potential brute force attacks targeting database instances. This detection helps identify potential security threats to database resources."
  documentation   = file("./detections/docs/sql_login_failed.md")
  severity        = "medium"
  query           = query.sql_login_failed
  display_columns = local.detection_display_columns

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

detection "sql_user_deleted" {
  title           = "SQL User Deleted"
  description     = "Detect successful deletion of users from SQL instances. This detection helps track changes to database access controls, ensuring compliance with security policies and helping identify potential account tampering or privilege removal attacks."
  documentation   = file("./detections/docs/sql_user_deleted.md")
  severity        = "medium"
  query           = query.sql_user_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "sql_ssl_certificate_deleted" {
  sql = <<-EOQ
    select
      ${local.sql_ssl_certificate_deleted_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'sqladmin.googleapis.com'
      and method_name ilike 'cloudsql.sslCerts.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "sql_login_failed" {
  sql = <<-EOQ
    select
      ${local.sql_login_failed_sql_columns}
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

query "sql_user_deleted" {
  sql = <<-EOQ
    select
      ${local.sql_user_deleted_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'sqladmin.googleapis.com'
      and method_name ilike 'cloudsql.users.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}