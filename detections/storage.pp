locals {
  storage_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/Storage"
  })

  detect_storage_set_iam_policies_sql_columns            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_storage_buckets_publicly_accessible_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "storage_detections" {
  title       = "Storage Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Storage events."
  type        = "detection"
  children = [
    detection.detect_storage_set_iam_policies,
    detection.detect_storage_buckets_publicly_accessible,
  ]

  tags = merge(local.storage_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_storage_set_iam_policies" {
  title           = "Detect Storage Set IAM Policies"
  description     = "Detect changes to storage IAM policies, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  documentation   = file("./detections/docs/detect_storage_set_iam_policies.md")
  severity        = "low"
  query           = query.detect_storage_set_iam_policies
  display_columns = local.detection_display_columns

  tags = merge(local.storage_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "detect_storage_buckets_publicly_accessible" {
  title           = "Detect Storage Buckets Publicly Accessible"
  description     = "Detect storage buckets that are publicly accessible, ensuring awareness of potential data exposure and mitigating associated security risks."
  documentation   = file("./detections/docs/detect_storage_buckets_publicly_accessible.md")
  severity        = "high"
  query           = query.detect_storage_buckets_publicly_accessible
  display_columns = local.detection_display_columns

  tags = merge(local.storage_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "detect_storage_set_iam_policies" {
  sql = <<-EOQ
    select
      ${local.detect_storage_set_iam_policies_sql_columns}
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

query "detect_storage_buckets_publicly_accessible" {
  sql = <<-EOQ
    select
      ${local.detect_storage_buckets_publicly_accessible_sql_columns}
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
