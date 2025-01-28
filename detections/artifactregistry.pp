locals {
  artifactregistry_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/ArtifactRegistry"
  })

}

benchmark "artifactregistry_detections" {
  title       = "Artifact Registry Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Artifact Registry events."
  type        = "detection"
  children = [
    detection.artifact_registry_package_deleted,
    detection.artifact_registry_publicly_accessible,
    detection.artifact_registry_repository_deleted,
  ]

  tags = merge(local.artifactregistry_common_tags, {
    type = "Benchmark"
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

// testing needed
query "artifact_registry_publicly_accessible" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
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

query "artifact_registry_package_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
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
      ${local.detection_sql_resource_column_resource_name}
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
