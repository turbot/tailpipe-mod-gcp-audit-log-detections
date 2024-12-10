locals {
  audit_log_admin_activity_monitoring_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/Monitoring"
  })

  audit_log_admin_activity_detect_unusual_resource_consumption_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_monitoring_detections" {
  title       = "Admin Activity Monitoring Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Monitoring Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_unusual_resource_consumption,
  ]

  tags = merge(local.audit_log_admin_activity_monitoring_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_unusual_resource_consumption" {
  title       = "Detect Unusual Resource Consumption"
  description = "Detect spikes in resource usage, which could indicate malicious activity like mining."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_unusual_resource_consumption

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1566"
  })
}

query "audit_log_admin_activity_detect_unusual_resource_consumption" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_unusual_resource_consumption_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      method_name ilike 'google.monitoring.v%.CreateTimeSeries'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
