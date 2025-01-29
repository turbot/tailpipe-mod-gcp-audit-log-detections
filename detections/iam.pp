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
    detection.iam_organization_policy_updated,
    detection.iam_owner_role_policy_set,
    detection.iam_service_account_access_token_generated,
    detection.iam_service_account_created,
    detection.iam_service_account_deleted,
    detection.iam_service_account_disabled,
    detection.iam_service_account_key_created,
    detection.iam_service_account_key_deleted,
    detection.iam_service_account_token_creator_role_assigned,
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

query "iam_service_account_token_creator_role_assigned" {
  sql = <<-EOQ
    with role_bindings as(
      select
        *,
        unnest(from_json((request -> 'policy' -> 'bindings'), '["JSON"]')) as bindings
      from
        gcp_audit_log
      where
        method_name ilike 'google.iam.admin.v%.setiampolicy'
    )
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      role_bindings
    where
      (bindings ->> 'role') like '%roles/iam.serviceAccountTokenCreator%'
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

query "iam_service_account_access_token_generated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      service_name = 'iamcredentials.googleapis.com'
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
      method_name ilike 'google.iam.admin.v%.deleteserviceaccountkey'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "iam_owner_role_policy_set" {
  sql = <<-EOQ
    with role_bindings as(
      select
        *,
        unnest(from_json((request -> 'policy' -> 'bindings'), '["JSON"]')) as bindings
      from
        gcp_audit_log
      where
        method_name ilike 'google.iam.admin.v%.setiampolicy'
    )
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      role_bindings
    where
      (bindings ->> 'role') = 'roles/owner'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
