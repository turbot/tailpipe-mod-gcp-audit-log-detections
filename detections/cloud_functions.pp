locals {
  cloud_functions_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/CloudFunctions"
  })
}

benchmark "cloud_functions_detections" {
  title       = "Cloud Function Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Cloud Function events."
  type        = "detection"
  children = [
    detection.cloud_functions_deleted,
    detection.cloud_functions_publicly_accessible,
  ]

  tags = merge(local.cloud_functions_common_tags, {
    type = "Benchmark"
  })
}

detection "cloud_functions_publicly_accessible" {
  title           = "Cloud Function Publicly Accessible"
  description     = "Detect when a Cloud Function was made publicly accessible to check for potential exposure to unauthorized access and security risks."
  documentation   = file("./detections/docs/cloud_functions_publicly_accessible.md")
  severity        = "high"
  query           = query.cloud_functions_publicly_accessible
  display_columns = local.detection_display_columns

  tags = merge(local.cloud_functions_common_tags, {
    mitre_attack_ids = "TA0001:T1199,TA0002:T1648"
  })
}

detection "cloud_functions_deleted" {
  title           = "Cloud Function Deleted"
  description     = "Detect when a Cloud Function was deleted to check for potential accidental loss of critical serverless resources or unauthorized deletions."
  documentation   = file("./detections/docs/cloud_functions_deleted.md")
  severity        = "medium"
  query           = query.cloud_functions_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.cloud_functions_common_tags, {
    mitre_attack_ids = "TA0002:T1648"
  })
}
// testing is needed
query "cloud_functions_publicly_accessible" {
  sql = <<-EOQ
    select 
      ${local.detection_sql_resource_column_resource_name}
    from 
      gcp_audit_log
    where
      lower(method_name) = 'google.cloud.functions.v%.cloudfunctionssservice.setiampolicy'
      ${local.detection_sql_where_conditions}
      and exists (
        select 1
        from unnest(json_extract(request, '$.policy.bindings[*].members[*]')::varchar[]) as t(member)
        where trim(both '"' from member) = 'allAuthenticatedUsers' or trim(both '"' from member) = 'allUsers'
      )
    order by
      timestamp desc;
  EOQ
}

query "cloud_functions_deleted" {
  sql = <<-EOQ
    select 
      ${local.detection_sql_resource_column_resource_name}
    from 
      gcp_audit_log
    where
      method_name ilike 'google.cloud.functions.v%.functionservice.deletefunction'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}