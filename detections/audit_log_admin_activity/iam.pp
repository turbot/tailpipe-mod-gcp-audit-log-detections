locals {
  audit_log_admin_activity_iam_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "IAM"
  })

  audit_log_admin_activity_detect_service_account_creations_sql_columns               = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_service_account_disabled_or_deleted_sql_columns     = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_service_account_access_token_generation_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")

}

detection_benchmark "audit_log_admin_activity_iam_detections" {
  title       = "Admin Activity IAM Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity IAM Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_service_account_creations,
    detection.audit_log_admin_activity_detect_service_account_disabled_or_deleted,
    detection.audit_log_admin_activity_detect_service_account_access_token_generation,
  ]

  tags = merge(local.audit_log_admin_activity_iam_detection_common_tags, {
    type = "Benchmark"
  })
}


detection "audit_log_admin_activity_detect_privilege_elevations" {
  title       = "Detect Privilege Elevations"
  description = "Detect privilege escalations by monitoring IAM policy changes."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_privilege_elevations

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "audit_log_admin_activity_detect_service_account_creations" {
  title       = "Detect Service Account Creations"
  description = "Detect newly created service accounts that might indicate potential misuse."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_service_account_creations

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1078"
  })
}

detection "audit_log_admin_activity_detect_service_account_disabled_or_deleted" {
  title       = "Detect Service Account Disabled or Deleted"
  description = "Detect disabled or deleted service accounts that might indicate malicious actions or disrupt resource access."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_service_account_disabled_or_deleted

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_service_account_access_token_generation" {
  title       = "Detect Service Account Access Token Generation"
  description = "Detect the generation of service account access tokens that might indicate unauthorized access attempts or potential data exposure."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_service_account_access_token_generation

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

/*
 * Queries
 */

query "audit_log_admin_activity_detect_service_account_creations" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_service_account_creations_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name like 'google.iam.admin.v%.CreateServiceAccount'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_service_account_disabled_or_deleted" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_service_account_disabled_or_deleted_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name in ('google.iam.admin.v1.ServiceAccounts.Delete', 'google.iam.admin.v1.ServiceAccounts.Disable')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_service_account_access_token_generation" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_service_account_access_token_generation_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'iamcredentials.googleapis.com'
      and method_name like 'google.iam.credentials.v%.IAMCredentials.GenerateAccessToken'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
