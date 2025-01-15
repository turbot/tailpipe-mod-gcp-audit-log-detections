locals {
  appengine_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/AppEngine"
  })

  detect_appengine_admin_api_execution_enabled_sql_columns         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_appengine_ingress_firewall_rule_deletions_sql_columns     = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_appengine_ingress_firewall_rule_modifications_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_appengine_ingress_firewall_rule_creations_sql_columns     = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "appengine_detections" {
  title       = "App Engine Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for App Engine events."
  type        = "detection"
  children = [
    detection.detect_appengine_ingress_firewall_rule_creations,
    detection.detect_appengine_ingress_firewall_rule_modifications,
    detection.detect_appengine_ingress_firewall_rule_deletions,
    detection.detect_appengine_admin_api_execution_enabled,
  ]

  tags = merge(local.appengine_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_appengine_ingress_firewall_rule_creations" {
  title           = "Detect App Engine Ingress Firewall Rule Creations"
  description     = "Detect creations to App Engine ingress firewall rules that may expose resources to threats."
  severity        = "medium"
  query           = query.detect_appengine_ingress_firewall_rule_creations
  display_columns = local.detection_display_columns

  tags = merge(local.appengine_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "detect_appengine_ingress_firewall_rule_modifications" {
  title           = "Detect App Engine Ingress Firewall Rule Modifications"
  description     = "Detect modifications to App Engine ingress firewall rules that may expose resources to threats."
  severity        = "medium"
  query           = query.detect_appengine_ingress_firewall_rule_modifications
  display_columns = local.detection_display_columns

  tags = merge(local.appengine_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "detect_appengine_ingress_firewall_rule_deletions" {
  title           = "Detect App Engine Ingress Firewall Rule Deletions"
  description     = "Detect deletions to App Engine ingress firewall rules that may expose resources to threats."
  severity        = "medium"
  query           = query.detect_appengine_ingress_firewall_rule_deletions
  display_columns = local.detection_display_columns

  tags = merge(local.appengine_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "detect_appengine_admin_api_execution_enabled" {
  title           = "Detect App Engine Admin API Executions Enabled"
  description     = "Detect when App Engine admin APIs are enabled, ensuring visibility into administrative configurations and monitoring for potential unauthorized changes."
  severity        = "medium"
  query           = query.detect_appengine_admin_api_execution_enabled
  display_columns = local.detection_display_columns

  tags = merge(local.appengine_common_tags, {
    mitre_attack_ids = "TA0002:T1648"
  })
}

query "detect_appengine_ingress_firewall_rule_creations" {
  sql = <<-EOQ
    select
      ${local.detect_appengine_ingress_firewall_rule_creations_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'appengine.googleapis.com'
      and method_name ilike 'google.appengine.v%.firewall.createingressrule'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_appengine_ingress_firewall_rule_modifications" {
  sql = <<-EOQ
    select
      ${local.detect_appengine_ingress_firewall_rule_modifications_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'appengine.googleapis.com'
      and method_name ilike 'google.appengine.v%.firewall.updateingressrule'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_appengine_ingress_firewall_rule_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_appengine_ingress_firewall_rule_deletions_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'appengine.googleapis.com'
      and method_name ilike 'google.appengine.v%.firewall.deleteingressrule'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
// testing needed
query "detect_appengine_admin_api_execution_enabled" {
  sql = <<-EOQ
    select
      ${local.detect_appengine_admin_api_execution_enabled_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'appengine.googleapis.com'
      and method_name ilike 'google.appengine.v%.apps.patch'
      and cast(request -> 'featureSettings' -> 'adminApiEnabled' as boolean) = true
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
