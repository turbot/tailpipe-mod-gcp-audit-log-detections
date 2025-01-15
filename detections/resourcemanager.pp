locals {
  resourcemanager_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/ResourceManager"
  })
  audit_logs_detect_project_level_iam_policy_change_sql_columns       = replace(local.audit_logs_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_logs_detect_login_without_mfa_sql_columns                     = replace(local.audit_logs_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_logs_detect_access_shared_resources_sql_columns               = replace(local.audit_logs_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_logs_detect_iam_policy_revoked_sql_columns                    = replace(local.audit_logs_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_logs_detect_iam_policy_to_enable_script_execution_sql_columns = replace(local.audit_logs_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_logs_detect_iam_policy_granting_owner_role_sql_columns        = replace(local.audit_logs_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_logs_detect_org_policy_revoked_sql_columns                    = replace(local.audit_logs_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_logs_resourcemanager_detections" {
  title       = "Resource Manager Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Resource Manager events."
  type        = "detection"
  children = [
    detection.audit_logs_detect_project_level_iam_policy_change,
    detection.audit_logs_detect_login_without_mfa,
    detection.audit_logs_detect_access_shared_resources,
    detection.audit_logs_detect_iam_policy_revoked,
    detection.audit_logs_detect_iam_policy_to_enable_script_execution,
    detection.audit_logs_detect_iam_policy_granting_owner_role,
    detection.audit_logs_detect_org_policy_revoked,
  ]

  tags = merge(local.resourcemanager_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_logs_detect_project_level_iam_policy_change" {
  title           = "Detect IAM Policies Set at Project Level"
  description     = "Detect changes to IAM policies at the project level, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_logs_detect_project_level_iam_policy_change
  display_columns = local.audit_logs_detection_display_columns

  tags = merge(local.resourcemanager_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

detection "audit_logs_detect_login_without_mfa" {
  title           = "Detect Logins Without MFA"
  description     = "Detect logins without MFA, ensuring visibility into access attempts that might indicate unauthorized activities or weak authentication practices."
  severity        = "medium"
  query           = query.audit_logs_detect_login_without_mfa
  display_columns = local.audit_logs_detection_display_columns

  tags = merge(local.resourcemanager_common_tags, {
    mitre_attack_ids = "TA0001:T1078"
  })
}

detection "audit_logs_detect_access_shared_resources" {
  title           = "Detect Access to Shared Resources"
  description     = "Detect access to shared resources that might indicate unauthorized access attempts or potential misuse of resource sharing configurations."
  severity        = "medium"
  query           = query.audit_logs_detect_access_shared_resources
  display_columns = local.audit_logs_detection_display_columns

  tags = merge(local.resourcemanager_common_tags, {
    mitre_attack_ids = "TA0001:T1078"
  })
}

detection "audit_logs_detect_iam_policy_revoked" {
  title           = "Detect IAM Policies Revoked"
  description     = "Detect IAM policies that have been revoked, ensuring visibility into changes that might impact access controls or signal unauthorized modifications."
  severity        = "medium"
  query           = query.audit_logs_detect_iam_policy_revoked
  display_columns = local.audit_logs_detection_display_columns

  tags = merge(local.resourcemanager_common_tags, {
    mitre_attack_ids = "TA0001:T1078"
  })
}

detection "audit_logs_detect_iam_policy_to_enable_script_execution" {
  title           = "Detect IAM Policies to Enable Script Execution"
  description     = "Detect IAM policies that enable script execution, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_logs_detect_iam_policy_to_enable_script_execution
  display_columns = local.audit_logs_detection_display_columns

  tags = merge(local.resourcemanager_common_tags, {
    mitre_attack_ids = "TA0002:T1059"
  })
}

detection "audit_logs_detect_iam_policy_granting_owner_role" {
  title           = "Detect IAM Policies Granting Owner Role"
  description     = "Detect IAM policies that grant the owner role, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_logs_detect_iam_policy_granting_owner_role
  display_columns = local.audit_logs_detection_display_columns

  tags = merge(local.resourcemanager_common_tags, {
    mitre_attack_ids = "TA0003:T1098,TA0003:T1136"
  })
}

detection "audit_logs_detect_org_policy_revoked" {
  title           = "Detect Org Policies Revoked"
  description     = "Detect org policies that have been revoked, ensuring visibility into changes that might impact access controls or signal unauthorized modifications."
  severity        = "medium"
  query           = query.audit_logs_detect_org_policy_revoked
  display_columns = local.audit_logs_detection_display_columns

  tags = merge(local.resourcemanager_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

query "audit_logs_detect_project_level_iam_policy_change" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_project_level_iam_policy_change_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'google.cloud.resourcemanager.v%.projects.setiampolicy'
      ${local.audit_log_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_logs_detect_login_without_mfa" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_login_without_mfa_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'google.cloud.identitytoolkit.v%.authenticate'
      and cast(request -> 'mfaVerified' as boolean) = false
      ${local.audit_log_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_logs_detect_access_shared_resources" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_access_shared_resources_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'google.cloud.accesscontextmanager.v%.accesssharedresource'
      ${local.audit_log_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
// TO DO: need to test
query "audit_logs_detect_iam_policy_revoked" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_iam_policy_revoked_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'google.cloud.resourcemanager.v%.projects.setiampolicy'
      and json_array_length(response -> 'bindings') = 0
      ${local.audit_log_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_logs_detect_iam_policy_to_enable_script_execution" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_iam_policy_to_enable_script_execution_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.setiampolicy'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'policy' -> 'bindings', '$[*].role') as varchar[])) as roles
        where roles = 'roles/cloudfunctions.invoker' or roles = 'roles/cloudfunctions.developer'
      )
      ${local.audit_log_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_logs_detect_iam_policy_granting_owner_role" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_iam_policy_granting_owner_role_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.setiampolicy'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'policy' -> 'bindings', '$[*].role') as varchar[])) as roles
        where roles = 'roles/owner'
      )
      ${local.audit_log_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_logs_detect_org_policy_revoked" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_org_policy_revoked_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'orgpolicy.googleapis.com'
      and method_name ilike 'google.cloud.orgpolicy.v%.policyservice.setorgpolicy'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'policy' -> 'spec' -> 'rules', '$[*]') as json[])) as rule_struct(rule)
        where json_extract(rule, '$.values.allowedValues') is not null
    )
      ${local.audit_log_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
