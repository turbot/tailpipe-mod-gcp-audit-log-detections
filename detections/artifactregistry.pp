locals {
  artifactregistry_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/ArtifactRegistry"
  })

  audit_logs_detect_artifact_registry_overwritten_sql_columns         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_logs_detect_artifact_registry_publicly_accessible_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_logs_detect_artifact_registry_package_deletion_sql_columns    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_logs_detect_artifact_registry_repository_deletion_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_logs_detect_encrypted_container_image_pushed_sql_columns      = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_logs_artifactregistry_detections" {
  title       = "Artifact Registry Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Artifact Registry events."
  type        = "detection"
  children = [
    detection.audit_logs_detect_artifact_registry_overwritten,
    detection.audit_logs_detect_artifact_registry_publicly_accessible,
    detection.audit_logs_detect_artifact_registry_with_no_layers,
    detection.audit_logs_detect_artifact_registry_package_deletion,
    detection.audit_logs_detect_artifact_registry_repository_deletion,
    detection.audit_logs_detect_encrypted_container_image_pushed,
  ]

  tags = merge(local.artifactregistry_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_logs_detect_artifact_registry_overwritten" {
  title           = "Detect Artifact Registry Overwritten"
  description     = "Detect Artifact Registry overwritten, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_logs_detect_artifact_registry_overwritten
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "audit_logs_detect_artifact_registry_publicly_accessible" {
  title           = "Detect Artifact Registry Publicly Accessible"
  description     = "Detect Artifact Registry publicly accessible, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_logs_detect_artifact_registry_publicly_accessible
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "audit_logs_detect_artifact_registry_with_no_layers" {
  title           = "Detect Artifact Registry with No Layers"
  description     = "Detect Artifact Registry with no layers, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_logs_detect_artifact_registry_with_no_layers
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "audit_logs_detect_artifact_registry_repository_deletion" {
  title           = "Detect Artifact Registry Repository Deletion"
  description     = "Detect Artifact Registry repository deletion, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_logs_detect_artifact_registry_repository_deletion
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "audit_logs_detect_artifact_registry_package_deletion" {
  title       = "Detect Artifact Registry Package Deletion"
  description = "Detect Artifact Registry package deletion, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_logs_detect_artifact_registry_package_deletion

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "audit_logs_detect_encrypted_container_image_pushed" {
  title           = "Detect Encrypted Container Image Pushed"
  description     = "Detect encrypted container image pushed, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_logs_detect_encrypted_container_image_pushed
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}
// testing needed
query "audit_logs_detect_artifact_registry_overwritten" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_artifact_registry_overwritten_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'artifactregistry.googleapis.com'
      and method_name ilike 'google.devtools.artifactregistry.v%.artifactregistry.uploadartifact'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'dockerImage' -> 'tags', '$[*]') as varchar[])) as tag
        where tag = 'latest'
      )
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
// testing needed
query "audit_logs_detect_artifact_registry_publicly_accessible" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_artifact_registry_publicly_accessible_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'artifactregistry.googleapis.com'
      and method_name ilike 'google.devtools.artifactregistry.v%.artifactregistry.setiampolicy'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'policy', '$.bindings[*].members[*]') as varchar[])) as member_struct(member)
        where member = 'allAuthenticatedUsers' or member = 'allUsers'
      )
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
// testing needed
query "audit_logs_detect_artifact_registry_with_no_layers" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_artifact_registry_overwritten_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'artifactregistry.googleapis.com'
      and method_name ilike 'google.devtools.artifactregistry.v%.artifactregistry.uploadartifact'
      and not exists (
        select *
        from unnest(cast(json_extract(request -> 'dockerImage' -> 'layers', '$[*]') as varchar[])) as layer
      )
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_logs_detect_artifact_registry_package_deletion" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_artifact_registry_package_deletion_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'artifactregistry.googleapis.com'
      and method_name ilike 'google.devtools.artifactregistry.v%.artifactregistry.deletepackage'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_logs_detect_artifact_registry_repository_deletion" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_artifact_registry_repository_deletion_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'artifactregistry.googleapis.com'
      and method_name ilike 'google.devtools.artifactregistry.v%.artifactregistry.deleterepository'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
// testing needed
query "audit_logs_detect_encrypted_container_image_pushed" {
  sql = <<-EOQ
    select
      ${local.audit_logs_detect_encrypted_container_image_pushed_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'artifactregistry.googleapis.com'
      and method_name ilike 'google.devtools.artifactregistry.v%.artifactregistry.uploadartifact'
      and json_extract(request -> 'dockerImage' -> 'encryption', '$.kmsKeyName') is not null
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
