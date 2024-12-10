locals {
  audit_log_admin_activity_cloudfunction_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/CloudFunctions"
  })

  audit_log_admin_activity_detect_cloudfunctions_publicly_accessible_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_cloudfunction_detections" {
  title       = "Admin Activity Cloudfunction Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Cloudfunction Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_cloudfunctions_publicly_accessible
  ]

  tags = merge(local.audit_log_admin_activity_cloudfunction_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_cloudfunctions_publicly_accessible" {
  title       = "Detect Cloud Functions Publicly Accessible"
  description = "Detects when a Cloud Function is made publicly accessible."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_cloudfunctions_publicly_accessible

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1199"
  })
}

query "audit_log_admin_activity_detect_cloudfunctions_publicly_accessible" {
  sql = <<-EOQ
    select 
      ${local.audit_log_admin_activity_detect_cloudfunctions_publicly_accessible_sql_columns}
    from 
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudfunctions.googleapis.com'
      and method_name ilike 'google.cloud.functions.v%.SetIamPolicy'
      ${local.audit_log_admin_activity_detection_where_conditions}
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'policy', '$.bindings[*].members[*]') as varchar[])) as member_struct(member)
        where member = 'allAuthenticatedUsers'
      )
    order by
      timestamp desc;
  EOQ
}