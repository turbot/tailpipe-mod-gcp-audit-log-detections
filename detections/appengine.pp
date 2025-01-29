locals {
  appengine_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/AppEngine"
  })
}

benchmark "appengine_detections" {
  title       = "App Engine Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for App Engine events."
  type        = "detection"
  children = [
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
  description     = "Detect when an App Engine ingress firewall rule was created to check for potential exposure of resources to unauthorized access or threats. New rules might unintentionally allow unrestricted access."
  documentation   = file("./detections/docs/appengine_ingress_firewall_rule_created.md")
  severity        = "medium"
  query           = query.appengine_ingress_firewall_rule_created
  display_columns = local.detection_display_columns

  tags = merge(local.appengine_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "appengine_ingress_firewall_rule_updated" {
  title           = "App Engine Ingress Firewall Rule Updated"
  description     = "Detect when an App Engine ingress firewall rule was updated to check for potential exposure of resources to unauthorized access. Changes to existing rules might weaken security boundaries."
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
  description     = "Detect when an App Engine ingress firewall rule was deleted to check for potential disruptions to security configurations, which could expose resources to unauthorized access or malicious activities."
  documentation   = file("./detections/docs/appengine_ingress_firewall_rule_deleted.md")
  severity        = "high"
  query           = query.appengine_ingress_firewall_rule_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.appengine_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

query "appengine_ingress_firewall_rule_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.appengine.v%.firewall.createingressrule'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "appengine_ingress_firewall_rule_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.appengine.v%.firewall.updateingressrule'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "appengine_ingress_firewall_rule_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.appengine.v%.firewall.deleteingressrule'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}