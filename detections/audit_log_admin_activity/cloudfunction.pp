locals {
  audit_log_admin_activity_cloudfunction_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/CloudFunctions"
  })

  audit_log_admin_activity_detect_cloudfunctions_publicly_accessible_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_cloudfunctions_operation_delete_sql_columns    = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_cloudfunctions_function_code_modifications_sql_columns    = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_logs_admin_activity_cloudfunction_detections" {
  title       = "Cloudfunction Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Cloudfunction events."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_cloudfunctions_publicly_accessible,
    detection.audit_log_admin_activity_detect_cloudfunctions_operation_delete,
    detection.audit_log_admin_activity_detect_cloudfunctions_function_code_modifications,
  ]

  tags = merge(local.audit_log_admin_activity_cloudfunction_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_cloudfunctions_publicly_accessible" {
  title           = "Detect Cloud Functions Publicly Accessible"
  description     = "Detect when Cloud Functions are made publicly accessible, ensuring awareness of potential exposure and mitigating security risks associated with unrestricted access."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_cloudfunctions_publicly_accessible
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1199,TA0002:T1648"
  })
}

detection "audit_log_admin_activity_detect_cloudfunctions_operation_delete" {
  title           = "Detect Cloud Functions Code Modifications"
  description     = "Detect when Cloud Functions are deleted, enabling prompt action to prevent accidental loss of critical serverless resources or potential security issues caused by unauthorized deletions."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_cloudfunctions_operation_delete
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0002:T1648"
  })
}

detection "audit_log_admin_activity_detect_cloudfunctions_function_code_modifications" {
  title           = "Detect Cloud Functions Code Modification"
  description     = "Detect when changes to the code of Google Cloud Functions. The updates can introduce malicious logic, disrupt service functionality, or deface public-facing applications. This is particularly critical for serverless environments where functions often handle sensitive operations or user interactions. Monitoring such changes helps prevent service degradation, unauthorized access, and reputational damage."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_cloudfunctions_function_code_modifications
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1531"
  })
}

query "audit_log_admin_activity_detect_cloudfunctions_publicly_accessible" {
  sql = <<-EOQ
    select 
      ${local.audit_log_admin_activity_detect_cloudfunctions_publicly_accessible_sql_columns}
    from 
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudfunctions.googleapis.com'
      and lower(method_name) = 'setiampolicy'
      ${local.audit_log_admin_activity_detection_where_conditions}
      and exists (
        select 1
        from unnest(json_extract(request, '$.policy.bindings[*].members[*]')::varchar[]) as t(member)
        where trim(both '"' from member) = 'allAuthenticatedUsers' or trim(both '"' from member) = 'allUsers'
      )
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_cloudfunctions_operation_delete" {
  sql = <<-EOQ
    select 
      ${local.audit_log_admin_activity_detect_cloudfunctions_operation_delete_sql_columns}
    from 
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudfunctions.googleapis.com'
      and method_name ilike 'google.cloud.functions.v%.functionservice.deletefunction'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_cloudfunctions_function_code_modifications" {
  sql = <<-EOQ
    select 
      ${local.audit_log_admin_activity_detect_cloudfunctions_function_code_modifications_sql_columns}
    from 
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudfunctions.googleapis.com'
      and method_name ilike 'google.cloud.functions.v%.functionservice.updatefunction'
      and json_extract(request, '$.function.build_config') is not null
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
