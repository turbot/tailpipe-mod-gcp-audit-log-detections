locals {
  audit_log_admin_activity_access_context_manager_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/AccessContextManager"
  })

  audit_log_admin_activity_detect_access_policy_deletion_updates_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_access_zone_deletion_updates_sql_columns   = replace(local.audit_log_admin_activity_detection_sql_columns, "accessPolicies", "accessZones")
  audit_log_admin_activity_detect_access_level_deletion_updates_sql_columns  = replace(local.audit_log_admin_activity_detection_sql_columns, "accessPolicies", "accessLevels")
}

benchmark "audit_log_admin_activity_access_context_manager_detections" {
  title       = "Admin Activity Access Context Manager Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Access Context Manager Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_access_policy_deletion_updates,
    detection.audit_log_admin_activity_detect_access_zone_deletion_updates,
    detection.audit_log_admin_activity_detect_access_level_deletion_updates,
  ]

  tags = merge(local.audit_log_admin_activity_access_context_manager_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_access_policy_deletion_updates" {
  title       = "Detect Access Policy Deletion Updates"
  description = "Detect deletions of access policies that might disrupt security configurations or expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_access_policy_deletion_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_access_zone_deletion_updates" {
  title       = "Detect Access Zone Deletion Updates"
  description = "Detect deletions of access zones that might disrupt security configurations or expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_access_zone_deletion_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_access_level_deletion_updates" {
  title       = "Detect Access Level Deletion Updates"
  description = "Detect deletions of access levels that might disrupt security configurations or expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_access_level_deletion_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_log_admin_activity_detect_access_policy_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_access_policy_deletion_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'accesscontextmanager.googleapis.com'
      and method_name = 'accesscontextmanager.accessPolicies.delete'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_access_zone_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_access_zone_deletion_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'accesscontextmanager.googleapis.com'
      and method_name = 'accesscontextmanager.accessPolicies.accessZones.delete'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_access_level_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_access_level_deletion_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'accesscontextmanager.googleapis.com'
      and method_name = 'accesscontextmanager.accessPolicies.accessLevels.delete'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}