locals {
  audit_log_data_access_iam_detection_common_tags = merge(local.audit_log_data_access_detection_common_tags, {
    service = "GCP/IAM"
  })
  audit_log_data_access_detect_service_account_access_token_generation_sql_columns        = replace(local.audit_log_data_access_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_data_access_detect_single_account_login_failure_sql_columns                   = replace(local.audit_log_data_access_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_data_access_detect_failed_service_account_access_token_generation_sql_columns = replace(local.audit_log_data_access_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_data_access_detect_service_account_signblob_failure_sql_columns               = replace(local.audit_log_data_access_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_logs_data_access_iam_detections" {
  title       = "IAM Detections"
  description = "This benchmark contains recommendations when scanning Data Acess audit logs for IAM events."
  type        = "detection"
  children = [
    detection.audit_log_data_access_detect_single_account_login_failure,
    detection.audit_log_data_access_detect_service_account_access_token_generation,
    detection.audit_log_data_access_detect_failed_service_account_access_token_generation,
    detection.audit_log_data_access_detect_service_account_signblob_failure,
  ]

  tags = merge(local.audit_log_data_access_iam_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_data_access_detect_service_account_access_token_generation" {
  title           = "Detect IAM Service Account Access Token Generations"
  description     = "Detect the generation of IAM service account access tokens that might indicate unauthorized access attempts or potential data exposures."
  severity        = "medium"
  query           = query.audit_log_data_access_detect_service_account_access_token_generation
  display_columns = local.audit_log_data_access_detection_display_columns

  tags = merge(local.audit_log_data_access_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1078,TA0005:T1548"
  })
}

detection "audit_log_data_access_detect_failed_service_account_access_token_generation" {
  title           = "Detect Failed Attempts of IAM Service Account Access Token Generations"
  description     = "Detect "
  severity        = "medium"
  query           = query.audit_log_data_access_detect_failed_service_account_access_token_generation
  display_columns = local.audit_log_data_access_detection_display_columns

  tags = merge(local.audit_log_data_access_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

detection "audit_log_data_access_detect_single_account_login_failure" {
  title           = "Detect Single Account Multiple Login Failures"
  description     = "Detect single user account has failed login attempt. This may indicate brute force attempt or compromised credential."
  severity        = "low"
  query           = query.audit_log_data_access_detect_single_account_login_failure
  display_columns = local.audit_log_data_access_detection_display_columns

  tags = merge(local.audit_log_data_access_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

detection "audit_log_data_access_detect_service_account_signblob_failure" {
  title           = "Detect Failed SignBlob Operations for Service Accounts"
  description     = "Detect failed attempts to sign binary blobs using service account credentials. Failed SignBlob operations may indicate unauthorized attempts to create signed content or potential service account compromise attempts. This detection helps identify potential abuse of service account signing capabilities."
  severity        = "medium"
  query           = query.audit_log_data_access_detect_service_account_signblob_failure
  display_columns = local.audit_log_data_access_detection_display_columns

  tags = merge(local.audit_log_data_access_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1552"
  })
}

query "audit_log_data_access_detect_single_account_login_failure" {
  sql = <<-EOQ
    select
      ${local.audit_log_data_access_detect_single_account_login_failure_sql_columns}
    from
      gcp_audit_log_data_access
    where
      service_name = 'iamcredentials.googleapis.com'
      and method_name ilike 'signjwt'
      and status.code = 7
    order by
      timestamp desc;
  EOQ
}

query "audit_log_data_access_detect_service_account_signblob_failure" {
  sql = <<-EOQ
    select
      ${local.audit_log_data_access_detect_service_account_signblob_failure_sql_columns}
    from
      gcp_audit_log_data_access
    where
      service_name = 'iamcredentials.googleapis.com'
      and method_name ilike 'signblob'
      and status.code = 7
    order by
      timestamp desc;
  EOQ
}

query "audit_log_data_access_detect_service_account_access_token_generation" {
  sql = <<-EOQ
    select
      ${local.audit_log_data_access_detect_service_account_access_token_generation_sql_columns}
    from
      gcp_audit_log_data_access
    where
      service_name = 'iamcredentials.googleapis.com'
      and method_name ilike 'generateaccesstoken'
      ${local.audit_log_data_access_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_data_access_detect_failed_service_account_access_token_generation" {
  sql = <<-EOQ
    select
      ${local.audit_log_data_access_detect_failed_service_account_access_token_generation_sql_columns}
    from
      gcp_audit_log_data_access
    where
      service_name = 'iamcredentials.googleapis.com'
      and method_name ilike 'generateaccesstoken'
      and status.code = 7
    order by
      timestamp desc;
  EOQ
}
