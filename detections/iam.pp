locals {
  iam_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/IAM"
  })

  detect_service_account_creation_sql_columns                             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_service_account_deletions_sql_columns                            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_disabled_service_account_sql_columns                             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_service_account_key_creation_sql_columns                         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_workload_identity_pool_provider_creation_sql_columns             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_iam_roles_granting_access_to_all_authenticated_users_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_iam_service_account_token_creator_role_sql_columns               = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_organization_iam_policy_change_sql_columns                       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_iam_workforce_pool_update_sql_columns                            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_iam_federated_identity_provider_creation_sql_columns             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_iam_policy_granting_apigateway_admin_role_sql_columns            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_high_privilege_iam_roles_sql_columns                             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_iam_federated_identity_provider_updation_sql_columns             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_iam_policy_removing_logging_admin_role_sql_columns               = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_iam_service_account_access_token_generations_sql_columns         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_single_account_login_failures_sql_columns                        = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_failed_iam_service_account_access_token_generations_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_service_account_signblob_failures_sql_columns                    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_service_account_key_deletions_sql_columns                        = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_iam_roles_permission_revocations_sql_columns                     = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "iam_detections" {
  title       = "IAM Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for IAM events."
  type        = "detection"
  children = [
    detection.detect_service_account_creation,
    detection.detect_service_account_key_creation,
    detection.detect_service_account_deletions,
    detection.detect_disabled_service_account,
    detection.detect_workload_identity_pool_provider_creation,
    detection.detect_iam_roles_granting_access_to_all_authenticated_users,
    detection.detect_iam_service_account_token_creator_role,
    detection.detect_organization_iam_policy_change,
    detection.detect_iam_workforce_pool_update,
    detection.detect_iam_federated_identity_provider_creation,
    detection.detect_iam_policy_granting_apigateway_admin_role,
    detection.detect_high_privilege_iam_roles,
    detection.detect_iam_federated_identity_provider_updation,
    detection.detect_iam_policy_removing_logging_admin_role,
    detection.detect_single_account_login_failures,
    detection.detect_iam_service_account_access_token_generations,
    detection.detect_failed_iam_service_account_access_token_generations,
    detection.detect_service_account_signblob_failures,
    detection.detect_service_account_key_deletions,
    detection.detect_iam_roles_permission_revocations,
  ]

  tags = merge(local.iam_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_service_account_creation" {
  title           = "Detect IAM Service Account Creations"
  description     = "Detect newly created IAM service accounts, providing visibility into potential misuse or unauthorized access to resources, and enabling timely investigation to maintain security."
  severity        = "medium"
  query           = query.detect_service_account_creation
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1078,TA0003:T1136"
  })
}

detection "detect_service_account_deletions" {
  title           = "Detect IAM Service Accounts Deletions"
  description     = "Detect deleted IAM service accounts that might indicate malicious actions or disrupt access to resources."
  severity        = "medium"
  query           = query.detect_service_account_deletions
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0003:T1098"
  })
}

detection "detect_disabled_service_account" {
  title           = "Detect Disabled IAM Service Accounts"
  description     = "Detect disabled IAM service accounts that might indicate unauthorized access attempts or potential data exposures."
  severity        = "medium"
  query           = query.detect_disabled_service_account
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0003:T1098"
  })
}

detection "detect_service_account_key_creation" {
  title           = "Detect IAM Service Account Key Creations"
  description     = "Detect the creations of IAM service account keys that might indicate potential misuse or unauthorized access attempts."
  query           = query.detect_service_account_key_creation
  severity        = "medium"
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0003:T1098,TA0003:T1136"
  })
}

detection "detect_workload_identity_pool_provider_creation" {
  title           = "Detect IAM Workload Identity Pool Provider Creations"
  description     = "Detect the creations of IAM workload identity pool providers that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_workload_identity_pool_provider_creation
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078"
  })
}

detection "detect_iam_roles_granting_access_to_all_authenticated_users" {
  title           = "Detect IAM Roles Granting Access to All Authenticated Users"
  description     = "Detect IAM roles granting access to all authenticated users, ensuring visibility into over-permissioned configurations that could pose security risks."
  severity        = "medium"
  query           = query.detect_iam_roles_granting_access_to_all_authenticated_users
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1199,TA0003:T1098,TA0005:T1548"
  })
}

detection "detect_iam_service_account_token_creator_role" {
  title           = "Detect IAM Service Account Token Creator Roles"
  description     = "Detect the assignments of IAM service account token creator roles that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_iam_service_account_token_creator_role
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1199,TA0003:T1136,TA0005:T1548"
  })
}

detection "detect_organization_iam_policy_change" {
  title           = "Detect Organization IAM Policy Changes"
  description     = "Detect changes to organization IAM policies that might expose resources to threats or indicate unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_organization_iam_policy_change
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1199"
  })
}

detection "detect_iam_workforce_pool_update" {
  title           = "Detect IAM Workforce Pool Updates"
  description     = "Detect updates to IAM workforce pools that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_iam_workforce_pool_update
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

detection "detect_iam_federated_identity_provider_creation" {
  title           = "Detect IAM Federated Identity Provider Creations"
  description     = "Detect the creations of IAM federated identity providers that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_iam_federated_identity_provider_creation
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "detect_iam_policy_granting_apigateway_admin_role" {
  title           = "Detect IAM Policies Granting Apigateway Admin Roles"
  description     = "Detect IAM policies granting apigateway admin roles that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_iam_policy_granting_apigateway_admin_role
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "detect_high_privilege_iam_roles" {
  title           = "Detect High Privilege IAM Roles"
  description     = "Detect the creations of high privilege IAM roles that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_high_privilege_iam_roles
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0005:T1548"
  })
}

detection "detect_iam_federated_identity_provider_updation" {
  title           = "Detect IAM Federated Identity Provider Updations"
  description     = "Detect the updations of IAM federated identity providers that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_iam_federated_identity_provider_updation
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "detect_iam_policy_removing_logging_admin_role" {
  title           = "Detect IAM Policy Removing Logging Admin Role"
  description     = "Detect the removal of logging admin roles from IAM policies that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_iam_policy_removing_logging_admin_role
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

detection "detect_iam_service_account_access_token_generations" {
  title           = "Detect IAM Service Account Access Token Generations"
  description     = "Detect the generation of IAM service account access tokens that might indicate unauthorized access attempts or potential data exposures."
  severity        = "medium"
  query           = query.detect_iam_service_account_access_token_generations
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0005:T1548"
  })
}

detection "detect_failed_iam_service_account_access_token_generations" {
  title           = "Detect Failed IAM Service Account Access Token Generations"
  description     = "Detect failed attempts to generate IAM service account access tokens, which may indicate unauthorized access attempts or misconfigurations leading to operational issues."
  severity        = "medium"
  query           = query.detect_failed_iam_service_account_access_token_generations
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

detection "detect_single_account_login_failures" {
  title           = "Detect Single Account Multiple Login Failures"
  description     = "Detect multiple failed login attempts for a single user account, which may indicate brute force attempts or compromised credentials."
  severity        = "low"
  query           = query.detect_single_account_login_failures
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

detection "detect_service_account_signblob_failures" {
  title           = "Detect Service Account SignBlob Failures"
  description     = "Detect failed attempts to sign binary blobs using service account credentials, which may indicate unauthorized attempts or potential service account compromise."
  severity        = "medium"
  query           = query.detect_service_account_signblob_failures
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1552"
  })
}

detection "detect_service_account_key_deletions" {
  title           = "Detect IAM Service Account Key Deletions"
  description     = "Detect deletions of IAM service account keys to check for potential misuse or unauthorized access attempts, which could disrupt services, erase evidence of malicious activity, or impact operational continuity."
  query           = query.detect_service_account_key_deletions
  severity        = "medium"
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0040:T1531"
  })
}

detection "detect_iam_roles_permission_revocations" {
  title           = "Detect IAM Roles Permission Revocations"
  description     = "Detect when IAM role permissions are revoked to check for disruptions to operations, restricted access to resources, or potential malicious activity that could impact the environment’s functionality or security."
  severity        = "medium"
  query           = query.detect_iam_roles_permission_revocations
  display_columns = local.audit_log_detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0040:T1531"
  })
}

/*
 * Queries
 */

query "detect_service_account_key_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_service_account_key_deletions_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v1.DeleteServiceAccountKey'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_iam_roles_permission_revocations" {
  sql = <<-EOQ
    select
      ${local.detect_iam_roles_permission_revocations_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v1.UpdateRole'
      and json_extract(cast(service_data as json), '$.permissionDelta.removedPermissions') is not null
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_service_account_creation" {
  sql = <<-EOQ
    select
      ${local.detect_service_account_creation_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.createserviceaccount'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_disabled_service_account" {
  sql = <<-EOQ
    select
      ${local.detect_disabled_service_account_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.disableserviceaccount'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_service_account_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_service_account_deletions_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.deleteserviceaccount'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_service_account_key_creation" {
  sql = <<-EOQ
    select
      ${local.detect_service_account_key_creation_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.createserviceaccountkey'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_workload_identity_pool_provider_creation" {
  sql = <<-EOQ
    select
      ${local.detect_workload_identity_pool_provider_creation_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.v%.createworkloadidentitypoolprovider'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_iam_roles_granting_access_to_all_authenticated_users" {
  sql = <<-EOQ
    select
      *
    from
      gcp_audit_log
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'setiampolicy'
      and json_extract(cast(request as json), '$.policy.bindings[*].members')::varchar like '%allAuthenticatedUsers%'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_iam_service_account_token_creator_role" {
  sql = <<-EOQ
    select
      ${local.detect_iam_service_account_token_creator_role_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.setiampolicy'
      and json_extract(cast(request as json), '$.policy.bindings[*].role')::varchar like '%roles/iam.serviceAccountTokenCreator%'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_organization_iam_policy_change" {
  sql = <<-EOQ
    select
      ${local.detect_organization_iam_policy_change_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'setiampolicy'
      and authorization_info::varchar like '%"permission":"resourcemanager.projects.setIamPolicy"%'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_iam_workforce_pool_update" {
  sql = <<-EOQ
    select
      ${local.detect_iam_workforce_pool_update_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.v%beta.workforcepools.updateworkforcepool'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_iam_federated_identity_provider_creation" {
  sql = <<-EOQ
    select
      ${local.detect_iam_federated_identity_provider_creation_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.v%beta.workforcepools.createworkforcepoolprovider'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_iam_policy_granting_apigateway_admin_role" {
  sql = <<-EOQ
    select
      ${local.detect_iam_policy_granting_apigateway_admin_role_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'setiampolicy'
      and json_extract(cast(request as json), '$.policy.bindings[*].role')::varchar like '%roles/apigateway.admin%'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_high_privilege_iam_roles" {
  sql = <<-EOQ
    select
      ${local.detect_high_privilege_iam_roles_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.createrole'
      and cast(json_extract(request, '$.role.included_permissions[*]') as varchar) like '%resourcemanager.projects.setIamPolicy%'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_iam_federated_identity_provider_updation" {
  sql = <<-EOQ
    select
      ${local.detect_iam_federated_identity_provider_updation_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.v%beta.workforcepools.updateworkforcepoolprovider'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_iam_policy_removing_logging_admin_role" {
  sql = <<-EOQ
    select
      ${local.detect_iam_policy_removing_logging_admin_role_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'setiampolicy'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'policy' -> 'bindings', '$[*]') as json[])) as binding_struct(binding)
        where json_extract(binding, '$.role') in ('roles/logging.admin', 'roles/logging.viewer')
        and json_array_length(json_extract(binding, '$.members')) = 0
      )
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_single_account_login_failures" {
  sql = <<-EOQ
    select
      ${local.detect_single_account_login_failures_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iamcredentials.googleapis.com'
      and method_name ilike 'signjwt'
      and status.code = 7
    order by
      timestamp desc;
  EOQ
}

query "detect_service_account_signblob_failures" {
  sql = <<-EOQ
    select
      ${local.detect_service_account_signblob_failures_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iamcredentials.googleapis.com'
      and method_name ilike 'signblob'
      and status.code = 7
    order by
      timestamp desc;
  EOQ
}

query "detect_iam_service_account_access_token_generations" {
  sql = <<-EOQ
    select
      ${local.detect_iam_service_account_access_token_generations_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iamcredentials.googleapis.com'
      and method_name ilike 'generateaccesstoken'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_failed_iam_service_account_access_token_generations" {
  sql = <<-EOQ
    select
      ${local.detect_failed_iam_service_account_access_token_generations_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iamcredentials.googleapis.com'
      and method_name ilike 'generateaccesstoken'
      and status.code = 7
    order by
      timestamp desc;
  EOQ
}
