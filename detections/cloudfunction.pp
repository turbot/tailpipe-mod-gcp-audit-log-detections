locals {
  cloudfunction_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/CloudFunctions"
  })

  cloudfunctions_publicly_accessible_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  cloudfunctions_operations_deleted_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  cloudfunctions_code_updated_sql_columns        = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "cloudfunction_detections" {
  title       = "Cloudfunction Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Cloudfunction events."
  type        = "detection"
  children = [
    detection.cloudfunctions_code_updated,
    detection.cloudfunctions_operations_deleted,
    detection.cloudfunctions_publicly_accessible,
  ]

  tags = merge(local.cloudfunction_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudfunctions_publicly_accessible" {
  title           = "Cloud Functions Publicly Accessible"
  description     = "Detect when Cloud Functions are made publicly accessible, ensuring awareness of potential exposure and mitigating security risks associated with unrestricted access."
  documentation   = file("./detections/docs/cloudfunctions_publicly_accessible.md")
  severity        = "high"
  query           = query.cloudfunctions_publicly_accessible
  display_columns = local.detection_display_columns

  tags = merge(local.cloudfunction_common_tags, {
    mitre_attack_ids = "TA0001:T1199,TA0002:T1648"
  })
}

detection "cloudfunctions_operations_deleted" {
  title           = "Cloud Functions Operations Deleted"
  description     = "Detect when Cloud Functions are deleted, enabling prompt action to prevent accidental loss of critical serverless resources or potential security issues caused by unauthorized deletions."
  documentation   = file("./detections/docs/cloudfunctions_operations_deleted.md")
  severity        = "medium"
  query           = query.cloudfunctions_operations_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.cloudfunction_common_tags, {
    mitre_attack_ids = "TA0002:T1648"
  })
}

detection "cloudfunctions_code_updated" {
  title           = "Cloud Functions Code Modified"
  description     = "Detect when changes to the code of Google Cloud Functions. The updates can introduce malicious logic, disrupt service functionality, or deface public-facing applications. This is particularly critical for serverless environments where functions often handle sensitive operations or user interactions. Monitoring such changes helps prevent service degradation, unauthorized access, and reputational damage."
  documentation   = file("./detections/docs/cloudfunctions_code_updated.md")
  severity        = "high"
  query           = query.cloudfunctions_code_updated
  display_columns = local.detection_display_columns

  tags = merge(local.cloudfunction_common_tags, {
    mitre_attack_ids = "TA0040:T1531"
  })
}


query "cloudfunctions_code_updated" {
  sql = <<-EOQ
    select 
      ${local.cloudfunctions_code_updated_sql_columns}
    from 
      gcp_audit_log
    where
      service_name = 'cloudfunctions.googleapis.com'
      and method_name ilike 'google.cloud.functions.v%.functionservice.updatefunction'
      and json_extract(request, '$.function.build_config') is not null
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "cloudfunctions_publicly_accessible" {
  sql = <<-EOQ
    select 
      ${local.cloudfunctions_publicly_accessible_sql_columns}
    from 
      gcp_audit_log
    where
      service_name = 'cloudfunctions.googleapis.com'
      and lower(method_name) = 'setiampolicy'
      ${local.detection_sql_where_conditions}
      and exists (
        select 1
        from unnest(json_extract(request, '$.policy.bindings[*].members[*]')::varchar[]) as t(member)
        where trim(both '"' from member) = 'allAuthenticatedUsers' or trim(both '"' from member) = 'allUsers'
      )
    order by
      timestamp desc;
  EOQ
}

query "cloudfunctions_operations_deleted" {
  sql = <<-EOQ
    select 
      ${local.cloudfunctions_operations_deleted_sql_columns}
    from 
      gcp_audit_log
    where
      service_name = 'cloudfunctions.googleapis.com'
      and method_name ilike 'google.cloud.functions.v%.functionservice.deletefunction'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
