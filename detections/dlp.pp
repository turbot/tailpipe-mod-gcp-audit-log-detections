locals {
  dlp_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/DLP"
  })

  dlp_reidentify_content_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "dlp_detections" {
  title       = "DLP Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for DLP events."
  type        = "detection"
  children = [
    detection.dlp_deidentify_content,
    detection.dlp_reidentify_content,
  ]

  tags = merge(local.dlp_common_tags, {
    type = "Benchmark"
  })
}

detection "dlp_reidentify_content" {
  title           = "DLP Reidentify Content"
  description     = "Detect reidentifications of content that could expose sensitive information or violate data privacy regulations, ensuring compliance and protecting against unauthorized data exposure."
  documentation   = file("./detections/docs/dlp_reidentify_content.md")
  severity        = "high"
  query           = query.dlp_reidentify_content
  display_columns = local.detection_display_columns

  tags = merge(local.dlp_common_tags, {
    mitre_attack_ids = "TA0009:T1119"
  })
}

detection "dlp_deidentify_content" {
  title           = "DLP Deidentify Content"
  description     = "Detect deidentifications of content that could expose sensitive information or violate data privacy regulations, ensuring compliance and protecting against unauthorized data exposure."
  documentation   = file("./detections/docs/dlp_deidentify_content.md")
  severity        = "high"
  query           = query.dlp_deidentify_content
  display_columns = local.detection_display_columns

  tags = merge(local.dlp_common_tags, {
    mitre_attack_ids = "TA0009:T1119"
  })
}

query "dlp_deidentify_content" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      service_name = 'dlp.googleapis.com'
      and method_name ilike 'google.privacy.dlp.v%.dlpservice.deidentifycontent'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "dlp_reidentify_content" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      service_name = 'dlp.googleapis.com'
      and method_name ilike 'google.privacy.dlp.v%.dlpservice.reidentifycontent'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
