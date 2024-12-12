locals {
  audit_log_admin_activity_artifactregistry_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/ArtifactRegistry"
  })

  audit_log_admin_activity_detect_artifact_registry_overwritten_sql_columns         = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_artifact_registry_publicly_accessible_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_artifactregistry_detections" {
  title       = "Admin Activity Artifact Registry Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Artifact Registry Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_artifact_registry_overwritten,
    detection.audit_log_admin_activity_detect_artifact_registry_publicly_accessible,
    detection.audit_log_admin_activity_detect_artifact_registry_with_no_layers,
  ]

  tags = merge(local.audit_log_admin_activity_artifactregistry_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_artifact_registry_overwritten" {
  title       = "Detect Artifact Registry Overwritten"
  description = "Detect Artifact Registry overwritten, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_artifact_registry_overwritten

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "audit_log_admin_activity_detect_artifact_registry_publicly_accessible" {
  title       = "Detect Artifact Registry Publicly Accessible"
  description = "Detect Artifact Registry publicly accessible, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_artifact_registry_publicly_accessible

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "audit_log_admin_activity_detect_artifact_registry_with_no_layers" {
  title       = "Detect Artifact Registry with No Layers"
  description = "Detect Artifact Registry with no layers, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_artifact_registry_with_no_layers

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

query "audit_log_admin_activity_detect_artifact_registry_overwritten" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_artifact_registry_overwritten_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'artifactregistry.googleapis.com'
      and method_name ilike 'google.devtools.artifactregistry.v%.artifactregistry.uploadartifact'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'dockerImage' -> 'tags', '$[*]') as varchar[])) as tag
        where tag = 'latest'
      )
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_artifact_registry_publicly_accessible" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_artifact_registry_publicly_accessible_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'artifactregistry.googleapis.com'
      and method_name ilike 'google.devtools.artifactregistry.v%.artifactregistry.setiampolicy'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'policy', '$.bindings[*].members[*]') as varchar[])) as member_struct(member)
        where member = 'allAuthenticatedUsers' or member = 'allUsers'
      )
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_artifact_registry_with_no_layers" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_artifact_registry_overwritten_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'artifactregistry.googleapis.com'
      and method_name ilike 'google.devtools.artifactregistry.v%.artifactregistry.uploadartifact'
      and not exists (
        select *
        from unnest(cast(json_extract(request -> 'dockerImage' -> 'layers', '$[*]') as varchar[])) as layer
      )
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}