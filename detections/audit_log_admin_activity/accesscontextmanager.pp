locals {
  audit_log_admin_activity_access_context_manager_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "AccessContextManager"
  })

  audit_log_admin_activity_detect_access_policy_deletion_updates_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_access_context_manager_detections" {
  title       = "Admin Activity Access Context Manager Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Access Context Manager Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_access_policy_deletion_updates,
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

query "audit_log_admin_activity_detect_access_policy_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_access_policy_deletion_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'accesscontextmanager.googleapis.com'
      and method_name in ('accesscontextmanager.accessPolicies.authorizedOrgsDescs.delete', 'accesscontextmanager.accessPolicies.accessZones.delete', 'accesscontextmanager.accessPolicies.accessLevels.delete', 'accesscontextmanager.accessPolicies.delete')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
