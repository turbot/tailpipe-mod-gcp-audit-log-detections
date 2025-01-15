locals {
  monitoring_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/Monitoring"
  })

  detect_unusual_resource_consumption_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_api_monitoring_disabled_sql_columns       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_api_monitoring_policy_deleted_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "monitoring_detections" {
  title       = "Monitoring Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Monitoring events."
  type        = "detection"
  children = [
    detection.detect_unusual_resource_consumption,
    detection.detect_api_monitoring_disabled,
    detection.detect_api_monitoring_policy_deleted,
  ]

  tags = merge(local.monitoring_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_unusual_resource_consumption" {
  title           = "Detect Unusual Resource Consumption"
  description     = "Detect spikes in resource usage that might indicate malicious activity, such as unauthorized cryptocurrency mining or other abnormal behaviors."
  severity        = "medium"
  query           = query.detect_unusual_resource_consumption
  display_columns = local.detection_display_columns

  tags = merge(local.monitoring_common_tags, {
    mitre_attack_ids = "TA0005:T1566"
  })
}

detection "detect_api_monitoring_disabled" {
  title           = "Detect API Monitoring Disabled"
  description     = "Detect when API monitoring is disabled, which might disrupt security configurations or expose resources to threats."
  severity        = "medium"
  query           = query.detect_api_monitoring_disabled
  display_columns = local.detection_display_columns

  tags = merge(local.monitoring_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

detection "detect_api_monitoring_policy_deleted" {
  title           = "Detect API Monitoring Policy Deleted"
  description     = "Detect when an API monitoring policy is deleted, which might disrupt security configurations or expose resources to threats."
  severity        = "medium"
  query           = query.detect_api_monitoring_policy_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.monitoring_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

query "detect_unusual_resource_consumption" {
  sql = <<-EOQ
    select
      ${local.detect_unusual_resource_consumption_sql_columns}
    from
      gcp_audit_log
    where
      method_name ilike 'google.monitoring.v%.createtimeseries'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_api_monitoring_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_api_monitoring_disabled_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'monitoring.googleapis.com'
      and method_name ilike 'google.monitoring.v%.metricservice.deletemetricdescriptor'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_api_monitoring_policy_deleted" {
  sql = <<-EOQ
    select
      ${local.detect_api_monitoring_policy_deleted_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'monitoring.googleapis.com'
      and method_name ilike 'google.monitoring.v%.alertpolicyservice.deletealertpolicy'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
