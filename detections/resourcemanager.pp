locals {
  resourcemanager_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/ResourceManager"
  })

}

benchmark "resourcemanager_detections" {
  title       = "Resource Manager Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Resource Manager events."
  type        = "detection"
  children = [
    detection.resourcemanager_iam_policy_set,
    detection.resourcemanager_owner_role_policy_set,
  ]

  tags = merge(local.resourcemanager_common_tags, {
    type = "Benchmark"
  })
}

detection "resourcemanager_iam_policy_set" {
  title           = "Resource Manager IAM Policy Set"
  description     = "Detect when a Resource Manager IAM policy was set to check for unauthorized changes that might expose resources to threats or compromise security."
  documentation   = file("./detections/docs/resourcemanager_iam_policy_set.md")
  severity        = "medium"
  query           = query.resourcemanager_iam_policy_set
  display_columns = local.detection_display_columns

  tags = merge(local.resourcemanager_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

detection "resourcemanager_owner_role_policy_set" {
  title           = "Resource Manager Owner Role Policy Set"
  description     = "Detect when an IAM policy granting the owner role was set to check for potential privilege escalation or unauthorized access."
  documentation   = file("./detections/docs/resourcemanager_owner_role_policy_set.md")
  severity        = "high"
  query           = query.resourcemanager_owner_role_policy_set
  display_columns = local.detection_display_columns

  tags = merge(local.resourcemanager_common_tags, {
    mitre_attack_ids = "TA0003:T1098,TA0003:T1136"
  })
}

query "resourcemanager_iam_policy_set" {
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

// testing is needed
query "resourcemanager_owner_role_policy_set" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.iam.admin.v%.setiampolicy'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'policy' -> 'bindings', '$[*].role') as varchar[])) as roles
        where roles = 'roles/owner'
      )
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
