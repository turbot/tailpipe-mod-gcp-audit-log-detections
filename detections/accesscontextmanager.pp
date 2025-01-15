locals {
  access_context_manager_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/AccessContextManager"
  })

  detect_access_policy_deletions_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_access_zone_deletions_sql_columns   = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_access_level_deletions_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "access_context_manager_detections" {
  title       = "Access Context Manager Detections"
  description = "This detection benchmark contains recommendations when scanning Admin Activity audit logs for Access Context Manager events."
  type        = "detection"
  children = [
    detection.detect_access_policy_deletions,
    detection.detect_access_zone_deletions,
    detection.detect_access_level_deletions,
  ]

  tags = merge(local.access_context_manager_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_access_policy_deletions" {
  title           = "Detect Access Policy Deletions"
  description     = "Detect deletions of access policies that might disrupt security configurations or expose resources to threats."
  severity        = "medium"
  query           = query.detect_access_policy_deletions
  display_columns = local.detection_display_columns

  tags = merge(local.access_context_manager_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "detect_access_zone_deletions" {
  title           = "Detect Access Zone Deletions"
  description     = "Detect deletions of access zones that might disrupt security configurations or expose resources to threats."
  severity        = "medium"
  query           = query.detect_access_zone_deletions
  display_columns = local.detection_display_columns

  tags = merge(local.access_context_manager_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "detect_access_level_deletions" {
  title           = "Detect Access Level Deletions"
  description     = "Detect deletions of access levels that might disrupt security configurations or expose resources to threats."
  severity        = "medium"
  query           = query.detect_access_level_deletions
  display_columns = local.detection_display_columns

  tags = merge(local.access_context_manager_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

query "detect_access_policy_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_access_policy_deletions_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'accesscontextmanager.googleapis.com'
      and method_name ilike 'accesscontextmanager.accesspolicies.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_access_zone_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_access_zone_deletions_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'accesscontextmanager.googleapis.com'
      and method_name ilike 'accesscontextmanager.accesspolicies.accesszones.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_access_level_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_access_level_deletions_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'accesscontextmanager.googleapis.com'
      and method_name ilike 'accesscontextmanager.accesspolicies.accesslevels.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}