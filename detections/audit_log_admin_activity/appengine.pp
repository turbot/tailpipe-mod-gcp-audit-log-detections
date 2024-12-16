locals {
  audit_log_admin_activity_appengine_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/AppEngine"
  })

  audit_log_admin_activity_detect_appengine_ingress_firewall_rule_changes_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_appengine_admin_api_execution_enabled_sql_columns   = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_appengine_detections" {
  title       = "Admin Activity App Engine Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity App Engine Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_appengine_ingress_firewall_rule_changes,
    detection.audit_log_admin_activity_detect_appengine_admin_api_execution_enabled,
  ]

  tags = merge(local.audit_log_admin_activity_appengine_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_appengine_ingress_firewall_rule_changes" {
  title           = "Detect App Engine Ingress Firewall Rule Changes"
  description     = "Detect changes to App Engine ingress firewall rules that may expose resources to threats."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_appengine_ingress_firewall_rule_changes
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_appengine_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "audit_log_admin_activity_detect_appengine_admin_api_execution_enabled" {
  title           = "Detect App Engine Admin API Executions Enabled"
  description     = "Detect when App Engine admin APIs are enabled, ensuring visibility into administrative configurations and monitoring for potential unauthorized changes."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_appengine_admin_api_execution_enabled
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_appengine_detection_common_tags, {
    mitre_attack_ids = "TA0002:T1648"
  })
}

query "audit_log_admin_activity_detect_appengine_ingress_firewall_rule_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_appengine_ingress_firewall_rule_changes_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'appengine.googleapis.com'
      and (method_name ilike 'google.appengine.v%.firewall.createingressrule' or method_name ilike 'google.appengine.v%.firewall.deleteingressrule' or method_name ilike 'google.appengine.v%.firewall.updateingressrule')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_appengine_admin_api_execution_enabled" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_appengine_admin_api_execution_enabled_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'appengine.googleapis.com'
      and method_name ilike 'google.appengine.v%.apps.patch'
      and cast(request -> 'featureSettings' -> 'adminApiEnabled' as boolean) = true
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
