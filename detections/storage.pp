locals {
  storage_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/Storage"
  })
}

benchmark "storage_detections" {
  title       = "Storage Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Storage events."
  type        = "detection"
  children = [
    detection.storage_bucket_iam_permission_granted_public_access,
    detection.storage_bucket_iam_permission_set,
  ]

  tags = merge(local.storage_common_tags, {
    type = "Benchmark"
  })
}

detection "storage_bucket_iam_permission_set" {
  title           = "Storage Bucket IAM Permission Set"
  description     = "Detect when a storage IAM permission was set to check for potential risks of exposing resources to threats or unauthorized access attempts."
  documentation   = file("./detections/docs/storage_bucket_iam_permission_set.md")
  severity        = "medium"
  query           = query.storage_bucket_iam_permission_set
  display_columns = local.detection_display_columns

  tags = local.storage_common_tags
}

detection "storage_bucket_iam_permission_granted_public_access" {
  title           = "Storage Bucket IAM Permission Granted Public Access"
  description     = "Detect when a storage bucket was made publicly accessible to check for potential risks of data exposure and associated security threats."
  documentation   = file("./detections/docs/storage_bucket_iam_permission_granted_public_access.md")
  severity        = "high"
  query           = query.storage_bucket_iam_permission_granted_public_access
  display_columns = local.detection_display_columns

  tags = local.storage_common_tags
}

query "storage_bucket_iam_permission_set" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'storage.setiampermissions'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "storage_bucket_iam_permission_granted_public_access" {
  sql = <<-EOQ
    with policy as(
      select
        *,
        unnest(from_json((service_data -> 'policyDelta' -> 'bindingDeltas'), '["JSON"]')) as bindings
      from
        gcp_audit_log
      where
        method_name ilike 'storage.setiampermissions'
    )
    select 
      ${local.detection_sql_resource_column_resource_name}
    from 
      policy
    where
      (bindings ->> 'member') = 'allUsers'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}