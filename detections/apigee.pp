locals {
  apigee_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/Apigee"
  })

  apigee_security_action_disabled_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "apigee_detections" {
  title       = "Apigee Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Apigee events."
  type        = "detection"
  children = [
    detection.apigee_security_action_disabled
  ]

  tags = merge(local.apigee_common_tags, {
    type = "Benchmark"
  })
}

detection "apigee_security_action_disabled" {
  title           = "Apigee Security Action Disabled"
  description     = "Detect log entries where a security action is disabled in Apigee that might expose resources to threats."
  documentation   = file("./detections/docs/apigee_security_action_disabled.md")
  severity        = "high"
  query           = query.apigee_security_action_disabled
  display_columns = local.detection_display_columns

  tags = merge(local.apigee_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "apigee_security_action_disabled" {
  sql = <<-EOQ
    select
      ${local.apigee_security_action_disabled_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'apigee.googleapis.com'
      and (method_name ilike 'google.cloud.apigee.v%.securityactionservice.disablesecurityaction')
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}