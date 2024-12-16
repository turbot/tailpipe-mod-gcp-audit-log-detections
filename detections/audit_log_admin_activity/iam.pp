locals {
  audit_log_admin_activity_iam_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/IAM"
  })

  audit_log_admin_activity_detect_service_account_creation_sql_columns                             = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_service_account_disabled_or_deleted_sql_columns                  = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_service_account_access_token_generation_sql_columns              = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_service_account_key_creation_sql_columns                         = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_workload_identity_pool_provider_creation_sql_columns             = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_iam_roles_granting_access_to_all_authenticated_users_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_iam_service_account_token_creator_role_sql_columns               = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_organization_iam_policy_change_sql_columns                       = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_iam_workforce_pool_update_sql_columns                            = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_iam_federated_identity_provider_creation_sql_columns             = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_iam_policy_granting_apigateway_admin_role_sql_columns            = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_iam_detections" {
  title       = "Admin Activity IAM Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity IAM Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_service_account_creation,
    detection.audit_log_admin_activity_detect_service_account_key_creation,
    detection.audit_log_admin_activity_detect_service_account_disabled_or_deleted,
    detection.audit_log_admin_activity_detect_service_account_access_token_generation,
    detection.audit_log_admin_activity_detect_workload_identity_pool_provider_creation,
    detection.audit_log_admin_activity_detect_iam_roles_granting_access_to_all_authenticated_users,
    detection.audit_log_admin_activity_detect_iam_service_account_token_creator_role,
    detection.audit_log_admin_activity_detect_organization_iam_policy_change,
    detection.audit_log_admin_activity_detect_iam_workforce_pool_update,
    detection.audit_log_admin_activity_detect_iam_federated_identity_provider_creation,
    detection.audit_log_admin_activity_detect_iam_policy_granting_apigateway_admin_role,
  ]

  tags = merge(local.audit_log_admin_activity_iam_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_service_account_creation" {
  title           = "Detect Service Account Creations"
  description     = "Detect newly created service accounts, providing visibility into potential misuse or unauthorized access to resources, and enabling timely investigation to maintain security."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_service_account_creation
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1078,TA0003:T1136"
  })
}

detection "audit_log_admin_activity_detect_service_account_disabled_or_deleted" {
  title           = "Detect Service Accounts Disabled or Deleted"
  description     = "Detect disabled or deleted service accounts that might indicate malicious actions or disrupt access to resources."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_service_account_disabled_or_deleted
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0003:T1098"
  })
}

detection "audit_log_admin_activity_detect_service_account_access_token_generation" {
  title           = "Detect Service Account Access Token Generations"
  description     = "Detect the generation of service account access tokens that might indicate unauthorized access attempts or potential data exposures."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_service_account_access_token_generation
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1078"
  })
}

detection "audit_log_admin_activity_detect_service_account_key_creation" {
  title           = "Detect Service Account Key Creations"
  description     = "Detect the creations of service account keys that might indicate potential misuse or unauthorized access attempts."
  query           = query.audit_log_admin_activity_detect_service_account_key_creation
  severity        = "medium"
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0003:T1098,TA0003:T1136"
  })
}

detection "audit_log_admin_activity_detect_workload_identity_pool_provider_creation" {
  title           = "Detect Workload Identity Pool Provider Creations"
  description     = "Detect the creations of workload identity pool providers that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_workload_identity_pool_provider_creation
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1078"
  })
}

detection "audit_log_admin_activity_detect_iam_roles_granting_access_to_all_authenticated_users" {
  title           = "Detect IAM Roles Granting Access to All Authenticated Users"
  description     = "Detect IAM roles granting access to all authenticated users, ensuring visibility into over-permissioned configurations that could pose security risks."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_iam_roles_granting_access_to_all_authenticated_users
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1199,TA0003:T1098"
  })
}

detection "audit_log_admin_activity_detect_iam_service_account_token_creator_role" {
  title           = "Detect IAM Service Account Token Creator Roles"
  description     = "Detect the assignments of IAM service account token creator roles that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_iam_service_account_token_creator_role
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1199,TA0003:T1136"
  })
}

detection "audit_log_admin_activity_detect_organization_iam_policy_change" {
  title           = "Detect Organization IAM Policy Changes"
  description     = "Detect changes to organization IAM policies that might expose resources to threats or indicate unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_organization_iam_policy_change
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1199"
  })
}

detection "audit_log_admin_activity_detect_iam_workforce_pool_update" {
  title           = "Detect IAM Workforce Pool Updates"
  description     = "Detect updates to IAM workforce pools that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_iam_workforce_pool_update
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

detection "audit_log_admin_activity_detect_iam_federated_identity_provider_creation" {
  title           = "Detect IAM Federated Identity Provider Creations"
  description     = "Detect the creations of IAM federated identity providers that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_iam_federated_identity_provider_creation
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "audit_log_admin_activity_detect_iam_policy_granting_apigateway_admin_role" {
  title           = "Detect IAM Policies Granting Apigateway Admin Roles"
  description     = "Detect IAM policies granting apigateway admin roles that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_iam_policy_granting_apigateway_admin_role
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

/*
 * Queries
 */

query "audit_log_admin_activity_detect_service_account_creation" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_service_account_creation_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.createserviceaccount'
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
      and (method_name ilike 'google.iam.admin.v%.serviceaccounts.delete' or method_name ilike 'google.iam.admin.v1.serviceaccounts.disable')
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
      and method_name ilike 'google.iam.credentials.v%.iamcredentials.generateaccesstoken'
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
      and method_name ilike 'google.iam.admin.v%.serviceaccounts.keys.create'
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
      and method_name ilike 'google.iam.v%.createworkloadidentitypoolprovider'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_iam_roles_granting_access_to_all_authenticated_users" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_iam_roles_granting_access_to_all_authenticated_users_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'setiampolicy'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'policy', '$.bindings[*].members[*]') as varchar[])) as member_struct(member)
        where member = 'allAuthenticatedUsers'
      )
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_iam_service_account_token_creator_role" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_iam_service_account_token_creator_role_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.v%.setiampolicy'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'policy' -> 'bindings', '$[*].role') as varchar[])) as roles
        where roles = 'roles/iam.serviceAccountTokenCreator'
      )
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_organization_iam_policy_change" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_organization_iam_policy_change_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'google.cloud.resourcemanager.v%.organizations.setiampolicy'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_iam_workforce_pool_update" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_iam_workforce_pool_update_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.v%beta.WorkforcePools.UpdateWorkforcePool'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_iam_federated_identity_provider_creation" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_iam_federated_identity_provider_creation_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.v%beta.workforcepools.createworkforcepoolprovider'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_iam_policy_granting_apigateway_admin_role" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_iam_policy_granting_apigateway_admin_role_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.setiampolicy'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'policy' -> 'bindings', '$[*].role') as varchar[])) as roles
        where roles = 'roles/apigateway.admin'
      )
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}