locals {
  audit_log_admin_activity_appengine_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "AppEngine"
  })

  audit_log_admin_activity_detect_appengine_ingress_firewall_rule_changes_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

detection_benchmark "audit_log_admin_activity_appengine_detections" {
  title       = "Admin Activity App Engine Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity App Engine Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_appengine_ingress_firewall_rule_changes,
  ]

  tags = merge(local.audit_log_admin_activity_appengine_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_appengine_ingress_firewall_rule_changes" {
  title       = "Detect App Engine Ingress Firewall Rule Changes"
  description = "Detect changes to App Engine ingress firewall rules that may expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_appengine_ingress_firewall_rule_changes

  tags = merge(local.audit_log_admin_activity_appengine_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
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
      and method_name in ('google.appengine.v1.Firewall.CreateIngressRule', 'google.appengine.v1.Firewall.DeleteIngressRule', 'google.appengine.v1.Firewall.UpdateIngressRule')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
