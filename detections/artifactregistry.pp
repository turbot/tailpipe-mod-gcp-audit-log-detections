locals {
  artifactregistry_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/ArtifactRegistry"
  })

  detect_overwritten_artifact_registry_artifacts_sql_columns             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_artifact_registries_publicly_accessible_sql_columns             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_artifact_registry_package_deletions_sql_columns                 = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_artifact_registry_repository_deletions_sql_columns               = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_artifact_registry_encrypted_container_images_pushed_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "artifactregistry_detections" {
  title       = "Artifact Registry Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Artifact Registry events."
  type        = "detection"
  children = [
    detection.detect_overwritten_artifact_registry_artifacts,
    detection.detect_artifact_registries_publicly_accessible,
    detection.detect_artifact_registry_artifacts_with_no_layers,
    detection.detect_artifact_registry_package_deletions,
    detection.detect_artifact_registry_repository_deletions,
    detection.detect_artifact_registry_encrypted_container_images_pushed,
  ]

  tags = merge(local.artifactregistry_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_overwritten_artifact_registry_artifacts" {
  title           = "Detect Overwritten Artifact Registry Artifacts"
  description     = "Detect overwritten Artifact Registry Artifacts, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_overwritten_artifact_registry_artifacts
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "detect_artifact_registries_publicly_accessible" {
  title           = "Detect Artifact Registries Publicly Accessible"
  description     = "Detect Artifact Registries publicly accessible, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "high"
  query           = query.detect_artifact_registries_publicly_accessible
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "detect_artifact_registry_artifacts_with_no_layers" {
  title           = "Detect Artifact Registry Artifacts with No Layers"
  description     = "Detect Artifact Registry Artifacts with no layers, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_artifact_registry_artifacts_with_no_layers
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "detect_artifact_registry_repository_deletions" {
  title           = "Detect Artifact Registry Repository Deletions"
  description     = "Detect Artifact Registry repository deletions, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  severity        = "high"
  query           = query.detect_artifact_registry_repository_deletions
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "detect_artifact_registry_package_deletions" {
  title       = "Detect Artifact Registry Package Deletions"
  description = "Detect Artifact Registry package deletions, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  severity    = "medium"
  query       = query.detect_artifact_registry_package_deletions

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "detect_artifact_registry_encrypted_container_images_pushed" {
  title           = "Detect Artifact Registry Encrypted Container Images Pushed"
  description     = "Detect Artifact Registry encrypted container images pushed, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_artifact_registry_encrypted_container_images_pushed
  display_columns = local.detection_display_columns

  tags = merge(local.artifactregistry_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}
// testing needed
query "detect_overwritten_artifact_registry_artifacts" {
  sql = <<-EOQ
    select
      ${local.detect_overwritten_artifact_registry_artifacts_sql_columns}
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
query "detect_artifact_registries_publicly_accessible" {
  sql = <<-EOQ
    select
      ${local.detect_artifact_registries_publicly_accessible_sql_columns}
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
query "detect_artifact_registry_artifacts_with_no_layers" {
  sql = <<-EOQ
    select
      ${local.detect_overwritten_artifact_registry_artifacts_sql_columns}
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

query "detect_artifact_registry_package_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_artifact_registry_package_deletions_sql_columns}
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

query "detect_artifact_registry_repository_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_artifact_registry_repository_deletions_sql_columns}
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
query "detect_artifact_registry_encrypted_container_images_pushed" {
  sql = <<-EOQ
    select
      ${local.detect_artifact_registry_encrypted_container_images_pushed_sql_columns}
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
