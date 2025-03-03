locals {
  app_engine_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    folder  = "App Engine"
    service = "GCP/AppEngine"
  })
}

benchmark "app_engine_detections" {
  title       = "App Engine Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for App Engine events."
  type        = "detection"
  children = [
    detection.app_engine_firewall_ingress_rule_created,
    detection.app_engine_firewall_ingress_rule_deleted,
    detection.app_engine_firewall_ingress_rule_updated,
  ]

  tags = merge(local.app_engine_common_tags, {
    type = "Benchmark"
  })
}

detection "app_engine_firewall_ingress_rule_created" {
  title           = "App Engine Firewall Ingress Rule Created"
  description     = "Detect when an App Engine Firewall Ingress Rule was created to check for potential exposure of resources to unauthorized access or threats. New rules might unintentionally allow unrestricted access."
  documentation   = file("./detections/docs/app_engine_firewall_ingress_rule_created.md")
  severity        = "medium"
  query           = query.app_engine_firewall_ingress_rule_created
  display_columns = local.detection_display_columns

  tags = merge(local.app_engine_common_tags, {
    mitre_attack_ids = "TA0005:T1578.005"
  })
}

detection "app_engine_firewall_ingress_rule_updated" {
  title           = "App Engine Firewall Ingress Rule Updated"
  description     = "Detect when an App Engine Firewall Ingress Rule was updated to check for potential exposure of resources to unauthorized access. Changes to existing rules might weaken security boundaries."
  documentation   = file("./detections/docs/app_engine_firewall_ingress_rule_updated.md")
  severity        = "high"
  query           = query.app_engine_firewall_ingress_rule_updated
  display_columns = local.detection_display_columns

  tags = merge(local.app_engine_common_tags, {
    mitre_attack_ids = "TA0005:T1578.005"
  })
}

detection "app_engine_firewall_ingress_rule_deleted" {
  title           = "App Engine Firewall Ingress Rule Deleted"
  description     = "Detect when an App Engine Firewall Ingress Rule was deleted to check for potential disruptions to security configurations, which could expose resources to unauthorized access or malicious activities."
  documentation   = file("./detections/docs/app_engine_firewall_ingress_rule_deleted.md")
  severity        = "high"
  query           = query.app_engine_firewall_ingress_rule_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.app_engine_common_tags, {
    mitre_attack_ids = "TA0005:T1578.005"
  })
}

query "app_engine_firewall_ingress_rule_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.app_engine.v%.firewall.createingressrule'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ

  tags = local.app_engine_common_tags
}

query "app_engine_firewall_ingress_rule_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.app_engine.v%.firewall.updateingressrule'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ

  tags = local.app_engine_common_tags
}

query "app_engine_firewall_ingress_rule_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.app_engine.v%.firewall.deleteingressrule'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ

  tags = local.app_engine_common_tags
}