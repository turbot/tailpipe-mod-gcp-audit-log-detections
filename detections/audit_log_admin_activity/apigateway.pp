locals {
  audit_log_admin_activity_apigateway_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/ApiGateway"
  })

  audit_log_admin_activity_detect_apigateway_configured_to_execute_backend_commands_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_apigateway_detections" {
  title       = "Admin Activity ApiGateway Logs"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity ApiGateway Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_apigateway_configured_to_execute_backend_commands
  ]

  tags = merge(local.audit_log_admin_activity_apigateway_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_apigateway_configured_to_execute_backend_commands" {
  title           = "Detect ApiGateway Configured to Execute Backend Commands"
  description     = "Detect log entries where an API Gateway is configured to execute backend commands."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_apigateway_configured_to_execute_backend_commands
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0002:T1651"
  })
}

query "audit_log_admin_activity_detect_apigateway_configured_to_execute_backend_commands" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_apigateway_configured_to_execute_backend_commands_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'apigateway.googleapis.com'
      and method_name ilike 'google.cloud.apigateway.v%.updateapiconfig'
      and exists(
        select *
        from unnest(cast(json_extract(request -> 'backendConfigs', '$[*].backendUri') as varchar[])) as uri_struct(uri)
        where uri like '%execute-command%'
      )
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}