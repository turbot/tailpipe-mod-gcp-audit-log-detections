locals {
  audit_log_admin_activity_storage_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/Storage"
  })

  audit_log_admin_activity_detect_storage_bucket_changes_sql_columns             = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_storage_bucket_enumeration_updates_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_storage_set_iam_policy_sql_columns             = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_storage_bucket_publicly_accessible_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_storage_bucket_object_rewrite_sql_columns      = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_storage_detections" {
  title       = "Admin Activity Storage Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Storage Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_storage_set_iam_policy,
    detection.audit_log_admin_activity_detect_storage_bucket_publicly_accessible,
    detection.audit_log_admin_activity_detect_storage_bucket_object_rewrite,
  ]

  tags = merge(local.audit_log_admin_activity_storage_detection_common_tags, {
    type = "Benchmark"
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

detection "audit_log_admin_activity_detect_storage_bucket_publicly_accessible" {
  title       = "Detect Publicly Accessible Storage Buckets"
  description = "Detect storage buckets that are publicly accessible."
  severity    = "high"
  query       = query.audit_log_admin_activity_detect_storage_bucket_publicly_accessible

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "audit_log_admin_activity_detect_storage_bucket_object_rewrite" {
  title       = "Detect Storage Bucket Object Rewrite"
  description = "Detect log entries where objects are rewritten in a storage bucket."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_storage_bucket_object_rewrite

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
// TO DO: Created resource to test in parker-aaa but logs doesnot show up
query "audit_log_admin_activity_detect_storage_bucket_publicly_accessible" {
  sql = <<-EOQ
    select 
      ${local.audit_log_admin_activity_detect_storage_bucket_publicly_accessible_sql_columns}
    from 
      gcp_audit_log_admin_activity
    where
      service_name = 'storage.googleapis.com'
      and method_name = 'storage.setIamPermissions'
      ${local.audit_log_admin_activity_detection_where_conditions}
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'defaultobjectacl', '$.bindings[*].members[*]') as varchar[])) as member_struct(member)
        where member = 'allusers'
      )
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_storage_bucket_object_rewrite" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_storage_bucket_object_rewrite_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'storage.googleapis.com'
      and method_name ilike 'storage.objects.rewrite'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
