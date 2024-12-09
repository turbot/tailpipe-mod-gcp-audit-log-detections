locals {
  audit_log_admin_activity_iam_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/IAM"
  })

  audit_log_admin_activity_detect_service_account_creations_sql_columns                = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_service_account_disabled_or_deleted_sql_columns      = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_service_account_access_token_generation_sql_columns  = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_service_account_key_creation_sql_columns             = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_workload_identity_pool_provider_creation_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_iam_detections" {
  title       = "Admin Activity IAM Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity IAM Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_service_account_creations,
    detection.audit_log_admin_activity_detect_service_account_key_creation,
    detection.audit_log_admin_activity_detect_service_account_disabled_or_deleted,
    detection.audit_log_admin_activity_detect_service_account_access_token_generation,
  ]

  tags = merge(local.audit_log_admin_activity_iam_detection_common_tags, {
    type = "Benchmark"
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
    mitre_attack_ids = "TA0001:T1078"
  })
}

detection "audit_log_admin_activity_detect_service_account_key_creation" {
  title       = "Detect Service Account Key Creation"
  description = "Detect the creation of service account keys that might indicate potential misuse or unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_service_account_key_creation

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1078"
  })
}

detection "audit_log_admin_activity_detect_workload_identity_pool_provider_creation" {
  title       = "Detect Workload Identity Pool Provider Creation"
  description = "Detect the creation of workload identity pool providers that might indicate potential misuse or unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_workload_identity_pool_provider_creation

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1078"
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
      and (method_name like 'google.iam.admin.v%.ServiceAccounts.Delete' or method_name like 'google.iam.admin.v1.ServiceAccounts.Disable')
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

query "audit_log_admin_activity_detect_service_account_key_creation" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_service_account_key_creation_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name like 'google.iam.admin.v%.ServiceAccounts.Keys.Create'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_workload_identity_pool_provider_creation" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_workload_identity_pool_provider_creation_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name like 'google.iam.v%.CreateWorkloadIdentityPoolProvider'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}