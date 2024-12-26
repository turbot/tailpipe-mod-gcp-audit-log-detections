locals {
  audit_log_admin_activity_dns_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/DNS"
  })

  audit_log_admin_activity_detect_dns_zone_deletions_sql_columns       = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_dns_zone_modifications_sql_columns   = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_dns_record_modifications_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_logs_admin_activity_dns_detections" {
  title       = "DNS Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for DNS events."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_dns_zone_deletions,
    detection.audit_log_admin_activity_detect_dns_zone_modifications,
    detection.audit_log_admin_activity_detect_dns_record_modifications,
    detection.audit_log_admin_activity_detect_dns_record_deletions
  ]

  tags = merge(local.audit_log_admin_activity_dns_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_dns_zone_deletions" {
  title           = "Detect DNS Zone Deletions"
  description     = "Detect deletions of DNS zones, ensuring visibility into changes that could disrupt domain configurations, compromise infrastructure, or expose systems to potential threats."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_dns_zone_deletions
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "audit_log_admin_activity_detect_dns_zone_modifications" {
  title           = "Detect DNS Zone Modifications"
  description     = "Detect modifications to DNS zones, ensuring visibility into changes that could disrupt domain configurations, compromise infrastructure, or expose systems to potential threats."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_dns_zone_modifications
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "audit_log_admin_activity_detect_dns_record_modifications" {
  title           = "Detect DNS Record Modifications"
  description     = "Detect modifications to DNS records, ensuring visibility into changes that could disrupt domain configurations, compromise infrastructure, or expose systems to potential threats."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_dns_record_modifications
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "audit_log_admin_activity_detect_dns_record_deletions" {
  title           = "Detect DNS Record Deletions"
  description     = "Detect deletions of DNS records, ensuring visibility into changes that could disrupt domain configurations, compromise infrastructure, or expose systems to potential threats."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_dns_record_deletions
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "audit_log_admin_activity_detect_dns_zone_deletions" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_dns_zone_deletions_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'dns.googleapis.com'
      and method_name ilike 'dns.managedzones.delete'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_dns_zone_modifications" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_dns_zone_modifications_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'dns.googleapis.com'
      and method_name ilike 'dns.managedzones.patch'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_dns_record_modifications" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_dns_record_modifications_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'dns.googleapis.com'
      and method_name ilike 'dns.resourcerecordsets.patch'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_dns_record_deletions" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_dns_record_modifications_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'dns.googleapis.com'
      and method_name ilike 'dns.resourceeecordsets.delete'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}