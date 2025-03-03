locals {
  sql_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    folder  = "SQL"
    service = "GCP/SQL"
  })

}

benchmark "sql_detections" {
  title       = "SQL Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for SQL events."
  type        = "detection"
  children = [
    detection.sql_ssl_certificate_deleted,
    detection.sql_user_deleted,
  ]

  tags = merge(local.sql_common_tags, {
    type = "Benchmark"
  })
}

detection "sql_ssl_certificate_deleted" {
  title           = "SQL SSL Certificate Deleted"
  description     = "Detect when an SQL SSL certificate was deleted to check for potential risks, such as exposing resources to unauthorized access or disruptions in secure database connections."
  documentation   = file("./detections/docs/sql_ssl_certificate_deleted.md")
  severity        = "medium"
  query           = query.sql_ssl_certificate_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

detection "sql_user_deleted" {
  title           = "SQL User Deleted"
  description     = "Detect when an SQL user was deleted to check for potential risks, such as unauthorized access changes, privilege removals, or policy violations impacting database security."
  documentation   = file("./detections/docs/sql_user_deleted.md")
  severity        = "low"
  query           = query.sql_user_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

query "sql_ssl_certificate_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'cloudsql.sslCerts.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ

  tags = local.sql_common_tags
}

query "sql_user_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'cloudsql.users.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ

  tags = local.sql_common_tags
}