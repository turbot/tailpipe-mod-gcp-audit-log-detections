locals {
  apigee_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/Apigee"
  })

  apigee_api_accessed_vulnerable_services_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "apigee_detections" {
  title       = "Apigee Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Apigee events."
  type        = "detection"
  children = [
    detection.apigee_api_accessed_vulnerable_services
  ]

  tags = merge(local.apigee_common_tags, {
    type = "Benchmark"
  })
}

detection "apigee_api_accessed_vulnerable_services" {
  title           = "Apigee API Accessed Vulnerable Services"
  description     = "Detect log entries where Apigee API is accessed to a vulnerable service."
  documentation   = file("./detections/docs/apigee_api_accessed_vulnerable_services.md")
  severity        = "high"
  query           = query.apigee_api_accessed_vulnerable_services
  display_columns = local.detection_display_columns

  tags = merge(local.apigee_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "apigee_api_accessed_vulnerable_services" {
  sql = <<-EOQ
    select
      ${local.apigee_api_accessed_vulnerable_services_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'apigee.googleapis.com'
      and (method_name ilike 'google.apigee.v%.accessresource' or method_name ilike 'google.apigee.v%.attackservice')
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}