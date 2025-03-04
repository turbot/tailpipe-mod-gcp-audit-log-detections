locals {
  dlp_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    folder  = "DLP"
    service = "GCP/DLP"
  })
}

benchmark "dlp_detections" {
  title       = "DLP Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for DLP events."
  type        = "detection"
  children = [
    detection.dlp_reidentify_content,
  ]

  tags = merge(local.dlp_common_tags, {
    type = "Benchmark"
  })
}

detection "dlp_reidentify_content" {
  title           = "DLP Re-identify Content"
  description     = "Detect when GCP DLP content was reidentified to check for potential exposure of sensitive information, ensuring compliance with data privacy regulations and mitigating unauthorized data reidentification risks."
  documentation   = file("./detections/docs/dlp_reidentify_content.md")
  severity        = "high"
  query           = query.dlp_reidentify_content
  display_columns = local.detection_display_columns

  tags = merge(local.dlp_common_tags, {
    mitre_attack_ids = "TA0005:T1140"
  })
}

query "dlp_reidentify_content" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.privacy.dlp.v%.dlpservice.reidentifycontent'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ

  tags = local.dlp_common_tags
}