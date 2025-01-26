locals {
  appengine_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/AppEngine"
  })

  appengine_admin_api_enabled_sql_columns             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  appengine_ingress_firewall_rule_deleted_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  appengine_ingress_firewall_rule_updated_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  appengine_ingress_firewall_rule_created_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "appengine_detections" {
  title       = "App Engine Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for App Engine events."
  type        = "detection"
  children = [
    detection.appengine_admin_api_enabled,
    detection.appengine_ingress_firewall_rule_created,
    detection.appengine_ingress_firewall_rule_deleted,
    detection.appengine_ingress_firewall_rule_updated,
  ]

  tags = merge(local.appengine_common_tags, {
    type = "Benchmark"
  })
}

detection "appengine_ingress_firewall_rule_created" {
  title           = "App Engine Ingress Firewall Rule Created"
  description     = "Detect creations to App Engine ingress firewall rules that may expose resources to threats."
  documentation   = file("./detections/docs/appengine_ingress_firewall_rule_created.md")
  severity        = "medium"
  query           = query.appengine_ingress_firewall_rule_created
  display_columns = local.detection_display_columns

  tags = merge(local.appengine_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "appengine_ingress_firewall_rule_updated" {
  title           = "App Engine Ingress Firewall Rule Modified"
  description     = "Detect modifications to App Engine ingress firewall rules that may expose resources to threats."
  documentation   = file("./detections/docs/appengine_ingress_firewall_rule_updated.md")
  severity        = "high"
  query           = query.appengine_ingress_firewall_rule_updated
  display_columns = local.detection_display_columns

  tags = merge(local.appengine_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "appengine_ingress_firewall_rule_deleted" {
  title           = "App Engine Ingress Firewall Rule Deleted"
  description     = "Detect deletions to App Engine ingress firewall rules that may expose resources to threats."
  documentation   = file("./detections/docs/appengine_ingress_firewall_rule_deleted.md")
  severity        = "high"
  query           = query.appengine_ingress_firewall_rule_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.appengine_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "appengine_admin_api_enabled" {
  title           = "App Engine Admin API Enabled"
  description     = "Detect when App Engine admin APIs are enabled, ensuring visibility into administrative configurations and monitoring for potential unauthorized changes."
  documentation   = file("./detections/docs/appengine_admin_api_enabled.md")
  severity        = "medium"
  query           = query.appengine_admin_api_enabled
  display_columns = local.detection_display_columns

  tags = merge(local.appengine_common_tags, {
    mitre_attack_ids = "TA0002:T1648"
  })
}

query "appengine_ingress_firewall_rule_created" {
  sql = <<-EOQ
    select
      ${local.appengine_ingress_firewall_rule_created_sql_columns}
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

query "appengine_ingress_firewall_rule_updated" {
  sql = <<-EOQ
    select
      ${local.appengine_ingress_firewall_rule_updated_sql_columns}
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

query "appengine_ingress_firewall_rule_deleted" {
  sql = <<-EOQ
    select
      ${local.appengine_ingress_firewall_rule_deleted_sql_columns}
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
query "appengine_admin_api_enabled" {
  sql = <<-EOQ
    select
      ${local.appengine_admin_api_enabled_sql_columns}
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
