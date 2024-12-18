locals {
  audit_log_admin_activity_monitoring_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/Monitoring"
  })

  audit_log_admin_activity_detect_unusual_resource_consumption_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_api_monitoring_disabled_sql_columns      = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_logs_admin_activity_monitoring_detections" {
  title       = "Monitoring Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Monitoring events."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_unusual_resource_consumption,
    detection.audit_log_admin_activity_detect_api_monitoring_disabled,
  ]

  tags = merge(local.audit_log_admin_activity_monitoring_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_unusual_resource_consumption" {
  title           = "Detect Unusual Resource Consumption"
  description     = "Detect spikes in resource usage that might indicate malicious activity, such as unauthorized cryptocurrency mining or other abnormal behaviors."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_unusual_resource_consumption
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1566"
  })
}

detection "audit_log_admin_activity_detect_api_monitoring_disabled" {
  title           = "Detect API Monitoring Disabled"
  description     = "Detect when API monitoring is disabled, which might disrupt security configurations or expose resources to threats."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_api_monitoring_disabled
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

query "audit_log_admin_activity_detect_unusual_resource_consumption" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_unusual_resource_consumption_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      method_name ilike 'google.monitoring.v%.createtimeseries'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_api_monitoring_disabled" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_api_monitoring_disabled_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'monitoring.googleapis.com'
      method_name ilike 'google.monitoring.v%.metricService.deletemetricdescriptor'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
