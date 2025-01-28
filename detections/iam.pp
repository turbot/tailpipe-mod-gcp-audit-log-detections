locals {
  iam_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/IAM"
  })
}

benchmark "iam_detections" {
  title       = "IAM Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for IAM events."
  type        = "detection"
  children = [
    detection.iam_federated_identity_provider_created,
    detection.iam_federated_identity_provider_updated,
    detection.iam_organization_policy_updated,
    detection.iam_owner_role_policy_set,
    detection.iam_policy_granted_apigateway_admin_role,
    detection.iam_role_granted_to_all_users,
    detection.iam_role_with_high_privileges_created,
    detection.iam_service_account_access_token_generated,
    detection.iam_service_account_created,
    detection.iam_service_account_deleted,
    detection.iam_service_account_disabled,
    detection.iam_service_account_key_created,
    detection.iam_service_account_key_deleted,
    detection.iam_service_account_token_creator_role_assigned,
    detection.iam_workforce_pool_updated,
    detection.iam_workload_identity_pool_provider_created,
  ]

  tags = merge(local.iam_common_tags, {
    type = "Benchmark"
  })
}

detection "iam_service_account_created" {
  title           = "IAM Service Account Created"
  description     = "Detect when an IAM service account was created, potentially indicating misuse or unauthorized access to resources. Monitoring service account creation helps identify security risks and ensures compliance with access policies."
  documentation   = file("./detections/docs/iam_service_account_created.md")
  severity        = "low"
  query           = query.iam_service_account_created
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0006:T1078,TA0003:T1136"
  })
}

detection "iam_service_account_key_created" {
  title           = "IAM Service Account Key Created"
  description     = "Detect when an IAM service account key was created, potentially indicating misuse or unauthorized access attempts. Monitoring service account key creation helps identify security risks and prevent unauthorized access to critical resources."
  documentation   = file("./detections/docs/iam_service_account_key_created.md")
  severity        = "low"
  query           = query.iam_service_account_key_created
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0003:T1098,TA0003:T1136"
  })
}

detection "iam_service_account_deleted" {
  title           = "IAM Service Account Deleted"
  description     = "Detect when an IAM service account was deleted, potentially indicating malicious actions or disrupting access to critical resources. Monitoring service account deletions helps identify unauthorized activities and ensures resource availability."
  documentation   = file("./detections/docs/iam_service_account_deleted.md")
  severity        = "high"
  query           = query.iam_service_account_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0003:T1098"
  })
}

detection "iam_service_account_disabled" {
  title           = "IAM Service Account Disabled"
  description     = "Detect when an IAM service account was disabled, which may indicate unauthorized access attempts, potential data exposure, or security policy enforcement. Monitoring disabled service accounts helps identify suspicious activities and ensure resource integrity."
  documentation   = file("./detections/docs/iam_service_account_disabled.md")
  severity        = "high"
  query           = query.iam_service_account_disabled
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0003:T1098"
  })
}

detection "iam_workload_identity_pool_provider_created" {
  title           = "IAM Workload Identity Pool Provider Created"
  description     = "Detect when an IAM workload identity pool provider was created, potentially indicating misuse or unauthorized access attempts. Monitoring workload identity pool provider creation helps identify security risks and ensures compliance with access control policies."
  documentation   = file("./detections/docs/iam_workload_identity_pool_provider_created.md")
  severity        = "medium"
  query           = query.iam_workload_identity_pool_provider_created
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078"
  })
}

detection "iam_role_granted_to_all_users" {
  title           = "IAM Role Granted to All Authenticated Users"
  description     = "Detect when an IAM role was granted access to all authenticated users, potentially exposing sensitive resources to over-permissioned configurations and increasing the risk of unauthorized access or misuse."
  documentation   = file("./detections/docs/iam_role_granted_to_all_users.md")
  severity        = "high"
  query           = query.iam_role_granted_to_all_users
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1199,TA0003:T1098,TA0005:T1548"
  })
}

detection "iam_service_account_token_creator_role_assigned" {
  title           = "IAM Service Account Token Creator Role Assigned"
  description     = "Detect when the IAM Service Account Token Creator role was assigned, which may indicate potential misuse or unauthorized access attempts. Monitoring this assignment helps identify suspicious activity and maintain control over token creation capabilities."
  documentation   = file("./detections/docs/iam_service_account_token_creator_role_assigned.md")
  severity        = "medium"
  query           = query.iam_service_account_token_creator_role_assigned
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1199,TA0003:T1136,TA0005:T1548"
  })
}

detection "iam_organization_policy_updated" {
  title           = "IAM Organization Policy Updated"
  description     = "Detect when an IAM organization policy was updated, potentially exposing resources to threats or indicating unauthorized access attempts. Monitoring policy changes ensures compliance with security requirements and prevents accidental or malicious misconfigurations."
  documentation   = file("./detections/docs/iam_organization_policy_updated.md")
  severity        = "medium"
  query           = query.iam_organization_policy_updated
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1199"
  })
}

detection "iam_workforce_pool_updated" {
  title           = "IAM Workforce Pool Updated"
  description     = "Detect when an IAM workforce pool was updated, potentially indicating misuse or unauthorized access attempts. Monitoring workforce pool updates helps ensure security compliance and prevents accidental or malicious misconfigurations."
  documentation   = file("./detections/docs/iam_workforce_pool_updated.md")
  severity        = "medium"
  query           = query.iam_workforce_pool_updated
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1098"
  })
}

detection "iam_federated_identity_provider_created" {
  title           = "IAM Federated Identity Provider Created"
  description     = "Detect when an IAM federated identity provider was created, potentially indicating misuse or unauthorized access attempts. Monitoring federated identity provider creation helps identify security risks and ensures compliance with identity and access management policies."
  documentation   = file("./detections/docs/iam_federated_identity_provider_created.md")
  severity        = "medium"
  query           = query.iam_federated_identity_provider_created
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "iam_policy_granted_apigateway_admin_role" {
  title           = "IAM Policy Granted API Gateway Admin Role"
  description     = "Detect when an API Gateway Admin role was granted by IAM policy, potentially indicating misuse or unauthorized access attempts. Monitoring such policy changes helps ensure security and prevents unauthorized administrative access to API Gateway resources."
  documentation   = file("./detections/docs/iam_policy_granted_apigateway_admin_role.md")
  severity        = "medium"
  query           = query.iam_policy_granted_apigateway_admin_role
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "iam_role_with_high_privileges_created" {
  title           = "IAM Role with High Privileges Created"
  description     = "Detect when a high privilege IAM role was created, potentially indicating misuse or unauthorized access attempts. Monitoring the creation of such roles helps mitigate risks associated with privilege escalation and unauthorized activities."
  documentation   = file("./detections/docs/iam_role_with_high_privileges_created.md")
  severity        = "high"
  query           = query.iam_role_with_high_privileges_created
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0005:T1548"
  })
}

detection "iam_federated_identity_provider_updated" {
  title           = "IAM Federated Identity Provider Updated"
  description     = "Detect when an IAM federated identity provider was updated, potentially indicating misuse or unauthorized access attempts. Monitoring updates to federated identity providers helps ensure compliance with security policies and prevents unauthorized changes."
  documentation   = file("./detections/docs/iam_federated_identity_provider_updated.md")
  severity        = "medium"
  query           = query.iam_federated_identity_provider_updated
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "iam_service_account_access_token_generated" {
  title           = "IAM Service Account Access Token Generated"
  description     = "Detect when an IAM service account access token was generated, potentially indicating unauthorized access attempts or data exposure. Monitoring access token generation helps identify suspicious activities and ensures compliance with security policies."
  documentation   = file("./detections/docs/iam_service_account_access_token_generated.md")
  severity        = "medium"
  query           = query.iam_service_account_access_token_generated
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0005:T1548"
  })
}

detection "iam_service_account_key_deleted" {
  title           = "IAM Service Account Key Deleted"
  description     = "Detect when an IAM service account key was deleted, potentially indicating misuse, unauthorized access attempts, or efforts to disrupt services and erase evidence of malicious activity. Monitoring key deletions helps ensure operational continuity and enhances security visibility."
  documentation   = file("./detections/docs/iam_service_account_key_deleted.md")
  severity        = "medium"
  query           = query.iam_service_account_key_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0040:T1531"
  })
}

detection "iam_owner_role_policy_set" {
  title           = "IAM Owner Role Policy Set"
  description     = "Detect when an IAM policy granting the owner role was set to check for potential privilege escalation or unauthorized access."
  documentation   = file("./detections/docs/iam_owner_role_policy_set.md")
  severity        = "high"
  query           = query.iam_owner_role_policy_set
  display_columns = local.detection_display_columns

  tags = merge(local.resourcemanager_common_tags, {
    mitre_attack_ids = "TA0003:T1098,TA0003:T1136"
  })
}

query "iam_service_account_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.iam.admin.v%.createserviceaccount'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_service_account_key_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.iam.admin.v%.createserviceaccountkey'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_service_account_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.iam.admin.v%.deleteserviceaccount'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_service_account_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.iam.admin.v%.disableserviceaccount'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_workload_identity_pool_provider_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.iam.v%.workloadidentitypools.createworkloadidentitypoolprovider'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
// testing is needed event exist in the bucket
query "iam_role_granted_to_all_users" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'cloudresourcemanager.v%.projects.setiampolicy'
      and json_extract(cast(request as json), '$.policy.bindings[*].members')::varchar like '%allUsers%'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
// testing is needed event exist in the bucket
query "iam_service_account_token_creator_role_assigned" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.iam.admin.v%.setiampolicy'
      and json_extract(cast(request as json), '$.policy.bindings[*].role')::varchar like '%roles/iam.serviceAccountTokenCreator%'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_organization_policy_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'cloudresourcemanager.v%.organizations.setiampolicy'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_workforce_pool_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.iam.admin.v%.workforcepools.updateworkforcepool'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_federated_identity_provider_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.iam.admin.v%.workforcepools.createworkforcepoolprovider'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
// testing is needed event exist in the bucket
query "iam_policy_granted_apigateway_admin_role" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
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
// testing is needed
query "iam_role_with_high_privileges_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.iam.admin.v%.createrole'
      and cast(json_extract(request, '$.role.included_permissions[*]') as varchar) like '%resourcemanager.projects.setIamPolicy%'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
// testing is needed
query "iam_federated_identity_provider_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.iam.admin.v%.workforcepools.updateworkforcepoolprovider'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_service_account_access_token_generated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'generateaccesstoken'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_service_account_key_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.iam.admin.v1.deleteserviceaccountkey'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

// testing is needed
query "iam_owner_role_policy_set" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.iam.admin.v%.setiampolicy'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'policy' -> 'bindings', '$[*].role') as varchar[])) as roles
        where roles = 'roles/owner'
      )
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
