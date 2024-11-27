locals {
  audit_log_detection_common_tags = {
    service = "GCP/AuditLogs"
  }

  audit_log_detect_unauthorized_access_attempts_sql_columns            = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_privilege_elevations_sql_columns                    = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_service_account_creations_sql_columns               = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_firewall_rule_changes_sql_columns                   = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_unusual_resource_consumption_sql_columns            = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

detection_benchmark "audit_log_detections" {
  title       = "GCP Audit Log Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Audit Logs."
  type        = "detection"
  children = [
    detection.audit_log_detect_unauthorized_access_attempts,
    detection.audit_log_detect_privilege_elevations,
    detection.audit_log_detect_service_account_creations,
    detection.audit_log_detect_firewall_rule_changes,
    detection.audit_log_detect_unusual_resource_consumption,
  ]

  tags = merge(local.audit_log_detection_common_tags, {
    type = "Benchmark"
  })
}

/*
 * Detections
 */

detection "audit_log_detect_unauthorized_access_attempts" {
  title       = "Detect Unauthorized Access Attempts"
  description = "Detect failed or unauthorized access attempts to GCP resources."
  severity    = "high"
  query       = query.audit_log_detect_unauthorized_access_attempts

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1078"
  })
}

detection "audit_log_detect_privilege_elevations" {
  title       = "Detect Privilege Elevations"
  description = "Detect privilege escalations by monitoring IAM policy changes."
  severity    = "medium"
  query       = query.audit_log_detect_privilege_elevations

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "audit_log_detect_service_account_creations" {
  title       = "Detect Service Account Creations"
  description = "Detect newly created service accounts that might indicate potential misuse."
  severity    = "medium"
  query       = query.audit_log_detect_service_account_creations

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1078"
  })
}

detection "audit_log_detect_firewall_rule_changes" {
  title       = "Detect Firewall Rule Changes"
  description = "Detect changes to firewall rules that may expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_detect_firewall_rule_changes

  references = [
    "https://cloud.google.com/vpc/docs/firewalls"
  ]

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "audit_log_detect_unusual_resource_consumption" {
  title       = "Detect Unusual Resource Consumption"
  description = "Detect spikes in resource usage, which could indicate malicious activity like mining."
  severity    = "medium"
  query       = query.audit_log_detect_unusual_resource_consumption

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1566"
  })
}

/*
 * Queries
 */

query "audit_log_detect_unauthorized_access_attempts" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_unauthorized_access_attempts_sql_columns}
    from
      gcp_audit_log_activity
    where
      method_name = 'google.logging.v2.WriteLogEntries'
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_privilege_elevations" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_privilege_elevations_sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name = 'SetIamPolicy'
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_service_account_creations" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_service_account_creations_sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name = 'CreateServiceAccount'
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_firewall_rule_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_firewall_rule_changes_sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name in ('insert', 'update', 'delete')
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_unusual_resource_consumption" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_unusual_resource_consumption_sql_columns}
    from
      gcp_audit_log_activity
    where
      method_name = 'google.monitoring.v3.CreateTimeSeries'
    order by
      timestamp desc;
  EOQ
}
