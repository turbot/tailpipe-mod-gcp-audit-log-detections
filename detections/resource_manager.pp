locals {
  resourcemanager_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/ResourceManager"
  })

}

benchmark "resource_manager_detections" {
  title       = "Resource Manager Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Resource Manager events."
  type        = "detection"
  children = [
    detection.resource_manager_iam_policy_set,
  ]

  tags = merge(local.resourcemanager_common_tags, {
    type = "Benchmark"
  })
}

detection "resource_manager_iam_policy_set" {
  title           = "Resource Manager IAM Policy Set"
  description     = "Detect when a Resource Manager IAM policy was set to check for unauthorized changes that might expose resources to threats or compromise security."
  documentation   = file("./detections/docs/resource_manager_iam_policy_set.md")
  severity        = "medium"
  query           = query.resource_manager_iam_policy_set
  display_columns = local.detection_display_columns

  tags = merge(local.resourcemanager_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

query "resource_manager_iam_policy_set" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'cloudresourcemanager.v%.projects.setiampolicy'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
