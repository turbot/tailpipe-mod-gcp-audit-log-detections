locals {
  artifactregistry_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/ArtifactRegistry"
  })

  artifact_registry_artifacts_overwritten_sql_columns            = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  artifact_registry_publicly_accessible_sql_columns              = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  artifact_registry_repository_deleted_sql_columns               = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  artifact_registry_package_deleted_sql_columns                  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  artifact_registry_encrypted_container_image_pushed_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "artifactregistry_detections" {
  title       = "Artifact Registry Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Artifact Registry events."
  type        = "detection"
  children = [
    detection.artifact_registry_artifacts_no_layers,
    detection.artifact_registry_artifacts_overwritten,
    detection.artifact_registry_encrypted_container_image_pushed,
    detection.artifact_registry_package_deleted,
    detection.artifact_registry_publicly_accessible,
    detection.artifact_registry_repository_deleted,
  ]

  tags = merge(local.artifactregistry_common_tags, {
    type = "Benchmark"
  })
}

detection "artifact_registry_artifacts_overwritten" {
  title           = "Artifact Registry Artifacts Overwritten"
  description     = "Detect overwritten Artifact Registry Artifacts, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  documentation   = file("./detections/docs/artifact_registry_artifacts_overwritten.md")
  severity        = "medium"
  query           = query.artifact_registry_artifacts_overwritten
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "artifact_registry_publicly_accessible" {
  title           = "Artifact Registry Publicly Accessible"
  description     = "Detect Artifact Registries publicly accessible, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  documentation   = file("./detections/docs/artifact_registry_publicly_accessible.md")
  severity        = "high"
  query           = query.artifact_registry_publicly_accessible
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "artifact_registry_artifacts_no_layers" {
  title           = "Artifact Registry Artifacts No Layers"
  description     = "Detect Artifact Registry Artifacts with no layers, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  documentation   = file("./detections/docs/artifact_registry_artifacts_no_layers.md")
  severity        = "medium"
  query           = query.artifact_registry_artifacts_no_layers
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "artifact_registry_repository_deleted" {
  title           = "Artifact Registry Repository Deleted"
  description     = "Detect Artifact Registry repository deletions, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  documentation   = file("./detections/docs/artifact_registry_repository_deleted.md")
  severity        = "high"
  query           = query.artifact_registry_repository_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "artifact_registry_package_deleted" {
  title         = "Artifact Registry Package Deleted"
  description   = "Detect Artifact Registry package deletions, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  documentation = file("./detections/docs/artifact_registry_package_deleted.md")
  severity      = "medium"
  query         = query.artifact_registry_package_deleted

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "artifact_registry_encrypted_container_image_pushed" {
  title           = "Artifact Registry Encrypted Container Image Pushed"
  description     = "Detect Artifact Registry encrypted container images pushed, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  documentation   = file("./detections/docs/artifact_registry_encrypted_container_image_pushed.md")
  severity        = "medium"
  query           = query.artifact_registry_encrypted_container_image_pushed
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}
// testing needed
query "artifact_registry_artifacts_overwritten" {
  sql = <<-EOQ
    select
      ${local.artifact_registry_artifacts_overwritten_sql_columns}
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
query "artifact_registry_publicly_accessible" {
  sql = <<-EOQ
    select
      ${local.artifact_registry_publicly_accessible_sql_columns}
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
query "artifact_registry_artifacts_no_layers" {
  sql = <<-EOQ
    select
      ${local.artifact_registry_artifacts_overwritten_sql_columns}
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

query "artifact_registry_package_deleted" {
  sql = <<-EOQ
    select
      ${local.artifact_registry_package_deleted_sql_columns}
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

query "artifact_registry_repository_deleted" {
  sql = <<-EOQ
    select
      ${local.artifact_registry_repository_deleted_sql_columns}
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
query "artifact_registry_encrypted_container_image_pushed" {
  sql = <<-EOQ
    select
      ${local.artifact_registry_encrypted_container_image_pushed_sql_columns}
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
