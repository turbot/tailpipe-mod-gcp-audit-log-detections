locals {
  apigee_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/Apigee"
  })
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
  description     = "Detect when a security action in Apigee was disabled to check for potential exposure of resources to unauthorized access or malicious threats. Disabling security actions can compromise API protections and increase risk to the organization."
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
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      (method_name ilike 'google.cloud.apigee.v%.securityactionservice.disablesecurityaction')
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}