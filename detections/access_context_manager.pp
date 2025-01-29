locals {
  access_context_manager_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/AccessContextManager"
  })

}

benchmark "access_context_manager_detections" {
  title       = "Access Context Manager Detections"
  description = "This detection benchmark contains recommendations when scanning Admin Activity audit logs for Access Context Manager events."
  type        = "detection"
  children = [
    detection.access_context_manager_access_level_deleted,
    detection.access_context_manager_policy_deleted,
  ]

  tags = merge(local.access_context_manager_common_tags, {
    type = "Benchmark"
  })
}

detection "access_context_manager_policy_deleted" {
  title           = "Access Context Manager Policy Deleted"
  description     = "Detect when an Access Context Manager policy was deleted to check for potential disruptions to security configurations, which could expose resources to unauthorized access or reduce compliance with security policies."
  documentation   = file("./detections/docs/access_context_manager_policy_deleted.md")
  severity        = "high"
  query           = query.access_context_manager_policy_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.access_context_manager_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "access_context_manager_access_level_deleted" {
  title           = "Access Context Manager Access Level Deleted"
  description     = "Detect when an Access Context Manager Access level was deleted to check for potential disruptions to security boundaries, which could expose resources to unauthorized access or compromise organizational policies."
  documentation   = file("./detections/docs/access_context_manager_access_level_deleted.md")
  severity        = "medium"
  query           = query.access_context_manager_access_level_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.access_context_manager_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

query "access_context_manager_policy_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'accesscontextmanager.policies.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "access_context_manager_access_level_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'accesscontextmanager.accesspolicies.accesslevels.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}