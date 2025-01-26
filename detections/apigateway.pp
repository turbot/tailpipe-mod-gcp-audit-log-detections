locals {
  apigateway_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/APIGateway"
  })

  apigateway_backend_command_execution_configured_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "apigateway_detections" {
  title       = "API Gateway Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for API Gateway events."
  type        = "detection"
  children = [
    detection.apigateway_backend_command_execution_configured
  ]

  tags = merge(local.apigateway_common_tags, {
    type = "Benchmark"
  })
}

detection "apigateway_backend_command_execution_configured" {
  title           = "API Gateway Backend Command Execution Configured"
  description     = "Detect log entries where an API Gateway is configured to execute backend commands that might expose resources to threats."
  documentation   = file("./detections/docs/apigateway_backend_command_execution_configured.md")
  severity        = "high"
  query           = query.apigateway_backend_command_execution_configured
  display_columns = local.detection_display_columns

  tags = merge(local.apigateway_common_tags, {
    mitre_attack_ids = "TA0002:T1651"
  })
}
// testing needed
query "apigateway_backend_command_execution_configured" {
  sql = <<-EOQ
    select
      ${local.apigateway_backend_command_execution_configured_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'apigateway.googleapis.com'
      and method_name ilike 'google.cloud.apigateway.v%.apigatewayservice.updateapiconfig'
      and exists(
        select *
        from unnest(cast(json_extract(request -> 'backendConfigs', '$[*].backendUri') as varchar[])) as uri_struct(uri)
        where uri like '%execute-command%'
      )
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}