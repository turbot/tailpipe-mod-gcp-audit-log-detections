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
    detection.storage_bucket_publicly_accessible,
    detection.storage_iam_policy_set,
  ]

  tags = merge(local.storage_common_tags, {
    type = "Benchmark"
  })
}

detection "storage_iam_policy_set" {
  title           = "Storage IAM Policy Set"
  description     = "Detect changes to storage IAM policies, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  documentation   = file("./detections/docs/storage_iam_policy_set.md")
  severity        = "low"
  query           = query.storage_iam_policy_set
  display_columns = local.detection_display_columns

  tags = merge(local.storage_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "storage_bucket_publicly_accessible" {
  title           = "Storage Bucket Publicly Accessible"
  description     = "Detect storage buckets that are publicly accessible, ensuring awareness of potential data exposure and mitigating associated security risks."
  documentation   = file("./detections/docs/storage_bucket_publicly_accessible.md")
  severity        = "high"
  query           = query.storage_bucket_publicly_accessible
  display_columns = local.detection_display_columns

  tags = merge(local.storage_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "storage_iam_policy_set" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      service_name = 'storage.googleapis.com'
      and method_name ilike 'storage.setiampermissions'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "storage_bucket_publicly_accessible" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from 
      gcp_audit_log
    where
      service_name = 'storage.googleapis.com'
      and method_name ilike 'storage.setiampermissions'
      and service_data is not null
      and json_extract(service_data, '$.policyDelta.bindingDeltas') != 'null'
      and service_data like '%"member":"allUsers"%'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}