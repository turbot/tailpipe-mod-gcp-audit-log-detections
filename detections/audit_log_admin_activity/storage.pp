locals {
  audit_log_admin_activity_storage_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "Storage"
  })

  audit_log_admin_activity_detect_storage_bucket_changes_sql_columns             = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_storage_bucket_enumeration_updates_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_storage_set_iam_policy_sql_columns             = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

detection_benchmark "audit_log_admin_activity_storage_detections" {
  title       = "Admin Activity Storage Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Storage Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_storage_bucket_changes,
    detection.audit_log_admin_activity_detect_storage_bucket_enumeration_updates,
    detection.audit_log_admin_activity_detect_storage_set_iam_policy,
  ]

  tags = merge(local.audit_log_admin_activity_storage_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_storage_bucket_enumeration_updates" {
  title       = "Detect Storage Bucket Enumeration Updates"
  description = "Detect enumeration of storage buckets that might indicate unauthorized access attempts or potential data exposure."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_storage_bucket_enumeration_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_storage_bucket_changes" {
  title       = "Detect Storage Bucket Changes"
  description = "Detect changes to storage buckets that could lead to data exposure, unauthorized access, or configuration drift."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_storage_bucket_changes

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_storage_set_iam_policy" {
  title       = "Detect Storage Set IAM Policy"
  description = "Detect changes to storage IAM policies that might expose resources to threats or indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_storage_set_iam_policy

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_log_admin_activity_detect_storage_set_iam_policy" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_storage_set_iam_policy_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'storage.googleapis.com'
      and method_name = 'storage.setIamPermissions'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_storage_bucket_enumeration_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_storage_bucket_enumeration_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'storage.googleapis.com'
      and method_name in ('storage.buckets.list', 'storage.buckets.listChannels')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_storage_bucket_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_storage_bucket_changes_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'storage.googleapis.com'
      and method_name in ('storage.buckets.update', 'storage.buckets.delete')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
