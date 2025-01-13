locals {
  audit_log_storage_detection_common_tags = merge(local.audit_logs_detection_common_tags, {
    service = "GCP/Storage"
  })

  audit_logs_detect_storage_set_iam_policy_sql_columns             = replace(local.audit_logs_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_logs_detect_storage_bucket_publicly_accessible_sql_columns = replace(local.audit_logs_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_logs_storage_detections" {
  title       = "Storage Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Storage events."
  type        = "detection"
  children = [
    detection.audit_logs_detect_storage_set_iam_policy,
    detection.audit_logs_detect_storage_bucket_publicly_accessible,
  ]

  tags = merge(local.audit_log_storage_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_logs_detect_storage_set_iam_policy" {
  title           = "Detect Storage Set IAM Policies"
  description     = "Detect changes to storage IAM policies, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_logs_detect_storage_set_iam_policy
  display_columns = local.audit_logs_detection_display_columns

  tags = merge(local.audit_logs_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "audit_logs_detect_storage_bucket_publicly_accessible" {
  title           = "Detect Publicly Accessible Storage Buckets"
  description     = "Detect storage buckets that are publicly accessible, ensuring awareness of potential data exposure and mitigating associated security risks."
  severity        = "high"
  query           = query.audit_logs_detect_storage_bucket_publicly_accessible
  display_columns = local.audit_logs_detection_display_columns

  tags = merge(local.audit_logs_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "audit_logs_detect_storage_set_iam_policy" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_storage_set_iam_policy_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'storage.googleapis.com'
      and method_name = 'storage.setIamPermissions'
      ${local.audit_log_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_logs_detect_storage_bucket_publicly_accessible" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_storage_bucket_publicly_accessible_sql_columns}
    from 
      gcp_audit_log
    where
      service_name = 'storage.googleapis.com'
      and method_name = 'storage.setIamPermissions'
      ${local.audit_log_detection_where_conditions}
      and service_data is not null
      and json_extract(service_data, '$.policyDelta.bindingDeltas') != 'null'
      and service_data like '%"member":"allUsers"%'
    order by
      timestamp desc;
  EOQ
}
