locals {
  audit_log_admin_activity_resourcemanager_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "ResourceManager"
  })
  audit_log_admin_activity_detect_project_level_iam_policy_change_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")

}

detection_benchmark "audit_log_admin_activity_resourcemanager_detections" {
  title       = "Admin Activity Resource Manager Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Resource Manager Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_project_level_iam_policy_change
  ]

  tags = merge(local.audit_log_admin_activity_resourcemanager_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_project_level_iam_policy_change" {
  title       = "Detect IAM Policy Set at Project Level"
  description = "Detect changes to IAM policies at the project level that might expose resources to threats or indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_project_level_iam_policy_change

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_log_admin_activity_detect_project_level_iam_policy_change" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_project_level_iam_policy_change_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name like 'google.cloud.resourcemanager.v%.Projects.SetIamPolicy'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
