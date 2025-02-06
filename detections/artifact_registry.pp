locals {
  artifact_registry_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/ArtifactRegistry"
  })
}

benchmark "artifact_registry_detections" {
  title       = "Artifact Registry Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Artifact Registry events."
  type        = "detection"
  children = [
    detection.artifact_registry_package_deleted,
    detection.artifact_registry_repository_deleted,
  ]

  tags = merge(local.artifact_registry_common_tags, {
    type = "Benchmark"
  })
}

detection "artifact_registry_repository_deleted" {
  title           = "Artifact Registry Repository Deleted"
  description     = "Detect when an Artifact Registry repository was deleted to check for potential disruptions to resource availability or unauthorized removal of critical storage repositories."
  documentation   = file("./detections/docs/artifact_registry_repository_deleted.md")
  severity        = "low"
  query           = query.artifact_registry_repository_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.artifact_registry_common_tags, {
    mitre_attack_ids = "TA0005:T1578.003"
  })
}

detection "artifact_registry_package_deleted" {
  title         = "Artifact Registry Package Deleted"
  description   = "Detect when an Artifact Registry package was deleted to check for potential loss of critical resources or unauthorized removal of packages."
  documentation = file("./detections/docs/artifact_registry_package_deleted.md")
  severity      = "low"
  query         = query.artifact_registry_package_deleted

  tags = merge(local.app_engine_common_tags, {
    mitre_attack_ids = "TA0005:T1578.003"
  })
}

query "artifact_registry_package_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.devtools.artifact_registry.v%.artifact_registry.deletepackage'
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
      method_name ilike 'google.devtools.artifact_registry.v%.artifact_registry.deleterepository'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}