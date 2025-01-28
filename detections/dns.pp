locals {
  dns_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/DNS"
  })

  dns_zone_deleted_sql_columns   = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  dns_zone_updated_sql_columns   = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  dns_record_updated_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "dns_detections" {
  title       = "DNS Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for DNS events."
  type        = "detection"
  children = [
    detection.dns_record_deleted,
    detection.dns_record_updated,
    detection.dns_zone_deleted,
    detection.dns_zone_updated,
  ]

  tags = merge(local.dns_common_tags, {
    type = "Benchmark"
  })
}

detection "dns_zone_deleted" {
  title           = "DNS Zone Deleted"
  description     = "Detect deletions of DNS zones, ensuring visibility into changes that could disrupt domain configurations, compromise infrastructure, or expose systems to potential threats."
  documentation   = file("./detections/docs/dns_zone_deleted.md")
  severity        = "high"
  query           = query.dns_zone_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.dns_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "dns_zone_updated" {
  title           = "DNS Zone Updated"
  description     = "Detect modifications to DNS zones, ensuring visibility into changes that could disrupt domain configurations, compromise infrastructure, or expose systems to potential threats."
  documentation   = file("./detections/docs/dns_zone_updated.md")
  severity        = "high"
  query           = query.dns_zone_updated
  display_columns = local.detection_display_columns

  tags = merge(local.dns_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "dns_record_updated" {
  title           = "DNS Record Updated"
  description     = "Detect modifications to DNS records, ensuring visibility into changes that could disrupt domain configurations, compromise infrastructure, or expose systems to potential threats."
  documentation   = file("./detections/docs/dns_record_updated.md")
  severity        = "high"
  query           = query.dns_record_updated
  display_columns = local.detection_display_columns

  tags = merge(local.dns_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "dns_record_deleted" {
  title           = "DNS Record Deleted"
  description     = "Detect deletions of DNS records, ensuring visibility into changes that could disrupt domain configurations, compromise infrastructure, or expose systems to potential threats."
  documentation   = file("./detections/docs/dns_record_deleted.md")
  severity        = "high"
  query           = query.dns_record_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.dns_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "dns_zone_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      service_name = 'dns.googleapis.com'
      and method_name ilike 'dns.managedzones.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "dns_zone_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      service_name = 'dns.googleapis.com'
      and method_name ilike 'dns.managedzones.patch'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "dns_record_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      service_name = 'dns.googleapis.com'
      and method_name ilike 'dns.resourcerecordsets.patch'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "dns_record_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      service_name = 'dns.googleapis.com'
      and method_name ilike 'dns.resourcerecordsets.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}