locals {
  audit_log_admin_activity_access_context_manager_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/AccessContextManager"
  })

  audit_log_admin_activity_detect_access_policy_deletions_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_access_zone_deletions_sql_columns   = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_access_level_deletions_sql_columns  = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_access_context_manager_detections" {
  title       = "Admin Activity Access Context Manager Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Access Context Manager Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_access_policy_deletions,
    detection.audit_log_admin_activity_detect_access_zone_deletions,
    detection.audit_log_admin_activity_detect_access_level_deletions,
  ]

  tags = merge(local.audit_log_admin_activity_access_context_manager_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_access_policy_deletions" {
  title           = "Detect Access Policy Deletions"
  description     = "Detect deletions of access policies that might disrupt security configurations or expose resources to threats."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_access_policy_deletions
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "audit_log_admin_activity_detect_access_zone_deletions" {
  title           = "Detect Access Zone Deletions"
  description     = "Detect deletions of access zones that might disrupt security configurations or expose resources to threats."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_access_zone_deletions
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "audit_log_admin_activity_detect_access_level_deletions" {
  title           = "Detect Access Level Deletions"
  description     = "Detect deletions of access levels that might disrupt security configurations or expose resources to threats."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_access_level_deletions
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

query "audit_log_admin_activity_detect_access_policy_deletions" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_access_policy_deletions_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'accesscontextmanager.googleapis.com'
      and method_name ilike 'accesscontextmanager.accesspolicies.delete'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_access_zone_deletions" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_access_zone_deletions_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'accesscontextmanager.googleapis.com'
      and method_name ilike 'accesscontextmanager.accesspolicies.accesszones.delete'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_access_level_deletions" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_access_level_deletions_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'accesscontextmanager.googleapis.com'
      and method_name ilike 'accesscontextmanager.accesspolicies.accesslevels.delete'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}