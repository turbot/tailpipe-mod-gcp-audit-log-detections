locals {
  audit_log_apigee_detection_common_tags = merge(local.audit_logs_detection_common_tags, {
    service = "GCP/Apigee"
  })

  audit_logs_detect_api_access_to_vulnerable_services_sql_columns = replace(local.audit_logs_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_logs_apigee_detections" {
  title       = "Apigee Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Apigee events."
  type        = "detection"
  children = [
    detection.audit_logs_detect_api_access_to_vulnerable_services
  ]

  tags = merge(local.audit_log_apigee_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_logs_detect_api_access_to_vulnerable_services" {
  title           = "Detect API Access to Vulnerable Services"
  description     = "Detect log entries where API is accessed to a vulnerable service."
  severity        = "medium"
  query           = query.audit_logs_detect_api_access_to_vulnerable_services
  display_columns = local.audit_logs_detection_display_columns

  tags = merge(local.audit_logs_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "audit_logs_detect_api_access_to_vulnerable_services" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_api_access_to_vulnerable_services_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'apigee.googleapis.com'
      and (method_name ilike 'google.apigee.v%.accessresource' or method_name ilike 'google.apigee.v%.attackservice')
      ${local.audit_log_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}