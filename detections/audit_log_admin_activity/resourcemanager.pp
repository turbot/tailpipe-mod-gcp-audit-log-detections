locals {
  audit_log_admin_activity_resourcemanager_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/ResourceManager"
  })
  audit_log_admin_activity_detect_project_level_iam_policy_change_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_login_without_mfa_sql_columns               = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_access_shared_resources_sql_columns         = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_iam_policy_revoked_sql_columns              = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_resourcemanager_detections" {
  title       = "Admin Activity Resource Manager Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Resource Manager Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_project_level_iam_policy_change,
    detection.audit_log_admin_activity_detect_login_without_mfa,
    detection.audit_log_admin_activity_detect_access_shared_resources,
    detection.audit_log_admin_activity_detect_iam_policy_revoked,
  ]

  tags = merge(local.audit_log_admin_activity_resourcemanager_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_project_level_iam_policy_change" {
  title       = "Detect IAM Policy Set at Project Level"
  description = "Detect changes to IAM policies at the project level that might expose resources to threats or indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_project_level_iam_policy_change

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_login_without_mfa" {
  title       = "Detect Login Without MFA"
  description = "Detect logins without MFA that might indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_login_without_mfa

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1078"
  })
}

detection "audit_log_admin_activity_detect_access_shared_resources" {
  title       = "Detect Access Shared Resources"
  description = "Detect access to shared resources that might indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_access_shared_resources

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1078"
  })
}

detection "audit_log_admin_activity_detect_iam_policy_revoked" {
  title       = "Detect IAM Policy Revoked"
  description = "Detect IAM policies that have been revoked."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_iam_policy_revoked

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1078"
  })
}

query "audit_log_admin_activity_detect_project_level_iam_policy_change" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_project_level_iam_policy_change_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name like 'google.cloud.resourcemanager.v%.Projects.SetIamPolicy'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_login_without_mfa" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_login_without_mfa_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name like 'google.cloud.identitytoolkit.v%.Authenticate'
      and cast(request -> 'mfaVerified' as boolean) = false
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_access_shared_resources" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_access_shared_resources_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name like 'google.cloud.accesscontextmanager.v%.AccessSharedResource'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
// TO DO: need to test
query "audit_log_admin_activity_detect_iam_policy_revoked" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_iam_policy_revoked_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name like 'google.cloud.resourcemanager.v%.Projects.SetIamPolicy'
      and json_array_length(response -> 'bindings') = 0
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}