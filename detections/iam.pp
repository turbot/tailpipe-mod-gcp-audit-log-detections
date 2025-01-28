locals {
  iam_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/IAM"
  })

  iam_service_account_created_sql_columns                        = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_service_account_deleted_sql_columns                        = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_service_account_disabled_sql_columns                       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_service_account_key_created_sql_columns                    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_workload_identity_pool_provider_created_sql_columns        = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_role_granted_to_all_users_sql_columns                      = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_service_account_token_creator_role_assigned_sql_columns    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_organization_policy_changed_sql_columns                    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_workforce_pool_updated_sql_columns                         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_federated_identity_provider_created_sql_columns            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_policy_granted_apigateway_admin_role_sql_columns           = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_role_with_high_privileges_created_sql_columns              = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_federated_identity_provider_updated_sql_columns            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_service_account_access_token_generated_sql_columns         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_service_account_access_token_generation_failed_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_single_account_login_failed_sql_columns                    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_service_account_signblob_failed_sql_columns                = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  iam_service_account_key_deleted_sql_columns                    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "iam_detections" {
  title       = "IAM Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for IAM events."
  type        = "detection"
  children = [
    detection.detect_service_account_creations,
    detection.detect_service_account_key_creations,
    detection.detect_service_account_deletions,
    detection.detect_disabled_service_accounts,
    detection.detect_workload_identity_pool_provider_creations,
    detection.detect_iam_roles_granting_access_to_all_authenticated_users,
    detection.detect_iam_service_account_token_creator_roles,
    detection.detect_organization_iam_policy_changes,
    detection.detect_iam_workforce_pool_updates,
    detection.detect_iam_federated_identity_provider_creations,
    detection.detect_iam_policy_granting_apigateway_admin_roles,
    detection.detect_high_privilege_iam_roles,
    detection.detect_iam_federated_identity_provider_updations,
    detection.detect_iam_policy_removing_logging_admin_roles,
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

detection "iam_service_account_created" {
  title           = "IAM Service Account Created"
  description     = "Detect newly created IAM service accounts, providing visibility into potential misuse or unauthorized access to resources, and enabling timely investigation to maintain security."
  severity        = "low"
  query           = query.iam_service_account_created
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1078,TA0003:T1136"
  })
}

detection "iam_service_account_key_created" {
  title           = "IAM Service Account Key Created"
  description     = "Detect the creations of IAM service account keys that might indicate potential misuse or unauthorized access attempts."
  severity        = "low"
  query           = query.iam_service_account_key_created
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0003:T1098,TA0003:T1136"
  })
}

detection "iam_service_account_deleted" {
  title           = "IAM Service Account Deleted"
  description     = "Detect deleted IAM service accounts that might indicate malicious actions or disrupt access to resources."
  severity        = "high"
  query           = query.iam_service_account_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0003:T1098"
  })
}

detection "iam_service_account_disabled" {
  title           = "IAM Service Account Disabled"
  description     = "Detect disabled IAM service accounts that might indicate unauthorized access attempts or potential data exposures."
  severity        = "high"
  query           = query.iam_service_account_disabled
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0003:T1098"
  })
}

detection "iam_workload_identity_pool_provider_created" {
  title           = "IAM Workload Identity Pool Provider Created"
  description     = "Detect the creations of IAM workload identity pool providers that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.iam_workload_identity_pool_provider_created
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078"
  })
}

detection "iam_role_granted_to_all_users" {
  title           = "IAM Role Granted To All Authenticated Users"
  description     = "Detect IAM roles granting access to all authenticated users, ensuring visibility into over-permissioned configurations that could pose security risks."
  severity        = "high"
  query           = query.iam_role_granted_to_all_users
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1199,TA0003:T1098,TA0005:T1548"
  })
}

detection "iam_service_account_token_creator_role_assigned" {
  title           = "IAM Service Account Token Creator Role Assigned"
  description     = "Detect the assignments of IAM service account token creator roles that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.iam_service_account_token_creator_role_assigned
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1199,TA0003:T1136,TA0005:T1548"
  })
}

detection "iam_organization_policy_changed" {
  title           = "IAM Organization Policy Changed"
  description     = "Detect changes to organization IAM policies that might expose resources to threats or indicate unauthorized access attempts."
  severity        = "medium"
  query           = query.iam_organization_policy_changed
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1199"
  })
}

detection "iam_workforce_pool_updated" {
  title           = "IAM Workforce Pool Updated"
  description     = "Detect updates to IAM workforce pools that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.iam_workforce_pool_updated
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

detection "iam_federated_identity_provider_created" {
  title           = "IAM Federated Identity Provider Created"
  description     = "Detect the creations of IAM federated identity providers that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.iam_federated_identity_provider_created
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "iam_policy_granted_apigateway_admin_role" {
  title           = "IAM Policy Granted Apigateway Admin Role"
  description     = "Detect IAM policies granting apigateway admin roles that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.iam_policy_granted_apigateway_admin_role
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "iam_role_with_high_privileges_created" {
  title           = "IAM Role With High Privileges Created"
  description     = "Detect the creations of high privilege IAM roles that might indicate potential misuse or unauthorized access attempts."
  severity        = "high"
  query           = query.iam_role_with_high_privileges_created
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0005:T1548"
  })
}

detection "iam_federated_identity_provider_updated" {
  title           = "IAM Federated Identity Provider Updated"
  description     = "Detect the updates of IAM federated identity providers that might indicate potential misuse or unauthorized access attempts."
  severity        = "medium"
  query           = query.iam_federated_identity_provider_updated
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "iam_service_account_access_token_generated" {
  title           = "IAM Service Account Access Token Generated"
  description     = "Detect the generation of IAM service account access tokens that might indicate unauthorized access attempts or potential data exposures."
  severity        = "medium"
  query           = query.iam_service_account_access_token_generated
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0005:T1548"
  })
}

detection "iam_service_account_access_token_generation_failed" {
  title           = "IAM Service Account Access Token Generation Failed"
  description     = "Detect failed attempts to generate IAM service account access tokens, which may indicate unauthorized access attempts or misconfigurations leading to operational issues."
  severity        = "medium"
  query           = query.iam_service_account_access_token_generation_failed
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

detection "iam_single_account_login_failed" {
  title           = "IAM Single Account Login Failed"
  description     = "Detect multiple failed login attempts for a single user account, which may indicate brute force attempts or compromised credentials."
  severity        = "low"
  query           = query.iam_single_account_login_failed
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

detection "iam_service_account_signblob_failed" {
  title           = "IAM Service Account SignBlob Failed"
  description     = "Detect failed attempts to sign binary blobs using service account credentials, which may indicate unauthorized attempts or potential service account compromise."
  severity        = "medium"
  query           = query.iam_service_account_signblob_failed
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1552"
  })
}

detection "iam_service_account_key_deleted" {
  title           = "IAM Service Account Key Deleted"
  description     = "Detect deletions of IAM service account keys to check for potential misuse or unauthorized access attempts, which could disrupt services, erase evidence of malicious activity, or impact operational continuity."
  severity        = "medium"
  query           = query.iam_service_account_key_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0040:T1531"
  })
}

query "iam_service_account_created" {
  sql = <<-EOQ
    select
      ${local.iam_service_account_created_sql_columns}
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

query "iam_service_account_key_created" {
  sql = <<-EOQ
    select
      ${local.iam_service_account_key_created_sql_columns}
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

query "iam_service_account_deleted" {
  sql = <<-EOQ
    select
      ${local.iam_service_account_deleted_sql_columns}
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

query "iam_service_account_disabled" {
  sql = <<-EOQ
    select
      ${local.iam_service_account_disabled_sql_columns}
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

query "iam_workload_identity_pool_provider_created" {
  sql = <<-EOQ
    select
      ${local.iam_workload_identity_pool_provider_created_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.createworkloadidentitypoolprovider'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_role_granted_to_all_users" {
  sql = <<-EOQ
    select
      ${local.iam_role_granted_to_all_users_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'setiampolicy'
      and json_extract(cast(request as json), '$.policy.bindings[*].members')::varchar like '%allUsers%'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_service_account_token_creator_role_assigned" {
  sql = <<-EOQ
    select
      ${local.iam_service_account_token_creator_role_assigned_sql_columns}
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

query "iam_organization_policy_changed" {
  sql = <<-EOQ
    select
      ${local.iam_organization_policy_changed_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'cloudresourcemanager.googleapis.com'
      and method_name ilike 'cloudresourcemanager.v%.organizations.setiampolicy'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_workforce_pool_updated" {
  sql = <<-EOQ
    select
      ${local.iam_workforce_pool_updated_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.workforcepools.updateworkforcepool'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_federated_identity_provider_created" {
  sql = <<-EOQ
    select
      ${local.iam_federated_identity_provider_created_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.workforcepools.createworkforcepoolprovider'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_policy_granted_apigateway_admin_role" {
  sql = <<-EOQ
    select
      ${local.iam_policy_granted_apigateway_admin_role_sql_columns}
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

query "iam_role_with_high_privileges_created" {
  sql = <<-EOQ
    select
      ${local.iam_role_with_high_privileges_created_sql_columns}
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

query "iam_federated_identity_provider_updated" {
  sql = <<-EOQ
    select
      ${local.iam_federated_identity_provider_updated_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v%.workforcepools.updateworkforcepoolprovider'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_service_account_access_token_generated" {
  sql = <<-EOQ
    select
      ${local.iam_service_account_access_token_generated_sql_columns}
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

query "iam_service_account_access_token_generation_failed" {
  sql = <<-EOQ
    select
      ${local.iam_service_account_access_token_generation_failed_sql_columns}
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

query "iam_single_account_login_failed" {
  sql = <<-EOQ
    select
      ${local.iam_single_account_login_failed_sql_columns}
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

query "iam_service_account_signblob_failed" {
  sql = <<-EOQ
    select
      ${local.iam_service_account_signblob_failed_sql_columns}
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

query "iam_service_account_key_deleted" {
  sql = <<-EOQ
    select
      ${local.iam_service_account_key_deleted_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'iam.googleapis.com'
      and method_name ilike 'google.iam.admin.v1.deleteserviceaccountkey'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
