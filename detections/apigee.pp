locals {
  apigee_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/Apigee"
  })

  detect_api_access_to_vulnerable_services_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "apigee_detections" {
  title       = "Apigee Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Apigee events."
  type        = "detection"
  children = [
    detection.detect_api_access_to_vulnerable_services
  ]

  tags = merge(local.apigee_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_api_access_to_vulnerable_services" {
  title           = "Detect API Access to Vulnerable Services"
  description     = "Detect log entries where API is accessed to a vulnerable service."
  severity        = "medium"
  query           = query.detect_api_access_to_vulnerable_services
  display_columns = local.detection_display_columns

  tags = merge(local.apigee_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "detect_api_access_to_vulnerable_services" {
  sql = <<-EOQ
    select
      ${local.detect_api_access_to_vulnerable_services_sql_columns}
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