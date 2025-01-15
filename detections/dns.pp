locals {
  dns_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/DNS"
  })

  detect_dns_zone_deletions_sql_columns       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_dns_zone_modifications_sql_columns   = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_dns_record_modifications_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "dns_detections" {
  title       = "DNS Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for DNS events."
  type        = "detection"
  children = [
    detection.detect_dns_zone_deletions,
    detection.detect_dns_zone_modifications,
    detection.detect_dns_record_modifications,
    detection.detect_dns_record_deletions
  ]

  tags = merge(local.dns_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_dns_zone_deletions" {
  title           = "Detect DNS Zone Deletions"
  description     = "Detect deletions of DNS zones, ensuring visibility into changes that could disrupt domain configurations, compromise infrastructure, or expose systems to potential threats."
  severity        = "medium"
  query           = query.detect_dns_zone_deletions
  display_columns = local.detection_display_columns

  tags = merge(local.dns_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "detect_dns_zone_modifications" {
  title           = "Detect DNS Zone Modifications"
  description     = "Detect modifications to DNS zones, ensuring visibility into changes that could disrupt domain configurations, compromise infrastructure, or expose systems to potential threats."
  severity        = "medium"
  query           = query.detect_dns_zone_modifications
  display_columns = local.detection_display_columns

  tags = merge(local.dns_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "detect_dns_record_modifications" {
  title           = "Detect DNS Record Modifications"
  description     = "Detect modifications to DNS records, ensuring visibility into changes that could disrupt domain configurations, compromise infrastructure, or expose systems to potential threats."
  severity        = "medium"
  query           = query.detect_dns_record_modifications
  display_columns = local.detection_display_columns

  tags = merge(local.dns_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "detect_dns_record_deletions" {
  title           = "Detect DNS Record Deletions"
  description     = "Detect deletions of DNS records, ensuring visibility into changes that could disrupt domain configurations, compromise infrastructure, or expose systems to potential threats."
  severity        = "medium"
  query           = query.detect_dns_record_deletions
  display_columns = local.detection_display_columns

  tags = merge(local.dns_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "detect_dns_zone_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_dns_zone_deletions_sql_columns}
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

query "detect_dns_zone_modifications" {
  sql = <<-EOQ
    select
      ${local.detect_dns_zone_modifications_sql_columns}
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

query "detect_dns_record_modifications" {
  sql = <<-EOQ
    select
      ${local.detect_dns_record_modifications_sql_columns}
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

query "detect_dns_record_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_dns_record_modifications_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'dns.googleapis.com'
      and method_name ilike 'dns.resourceeecordsets.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}