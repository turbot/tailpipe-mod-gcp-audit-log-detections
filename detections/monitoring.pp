locals {
  monitoring_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    folder  = "Monitoring"
    service = "GCP/Monitoring"
  })
}

benchmark "monitoring_detections" {
  title       = "Monitoring Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Monitoring events."
  type        = "detection"
  children = [
    detection.monitoring_alert_policy_deleted,
    detection.monitoring_metric_descriptor_deleted,
  ]

  tags = local.monitoring_common_tags
}

detection "monitoring_metric_descriptor_deleted" {
  title           = "Monitoring Metric Descriptor Deleted"
  description     = "Detect when a monitoring metric descriptor was deleted, potentially disrupting monitoring configurations or indicating unauthorized access attempts. Monitoring metric descriptor deletions helps ensure the integrity of monitoring setups and mitigates security risks."
  documentation   = file("./detections/docs/monitoring_metric_descriptor_deleted.md")
  severity        = "medium"
  query           = query.monitoring_metric_descriptor_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.monitoring_common_tags, {
    mitre_attack_ids = "TA0005:T1578.005"
  })
}

detection "monitoring_alert_policy_deleted" {
  title           = "Monitoring Alert Policy Deleted"
  description     = "Detect when a monitoring alert policy was deleted, potentially disrupting alert configurations or indicating unauthorized access attempts. Monitoring alert policy deletions helps maintain the integrity of alerting systems and mitigates security risks."
  documentation   = file("./detections/docs/monitoring_alert_policy_deleted.md")
  severity        = "medium"
  query           = query.monitoring_alert_policy_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.monitoring_common_tags, {
    mitre_attack_ids = "TA0005:T1578.005"
  })
}

query "monitoring_metric_descriptor_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.monitoring.v%.metricservice.deletemetricdescriptor'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ

  tags = local.monitoring_common_tags
}

query "monitoring_alert_policy_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.monitoring.v%.alertpolicyservice.deletealertpolicy'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ

  tags = local.monitoring_common_tags
}