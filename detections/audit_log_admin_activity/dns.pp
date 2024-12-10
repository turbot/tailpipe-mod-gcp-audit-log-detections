locals {
  audit_log_admin_activity_dns_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/DNS"
  })

  audit_log_admin_activity_detect_dns_zone_changes_sql_columns         = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_dns_record_modifications_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_dns_detections" {
  title       = "Admin Activity DNS Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity DNS Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_dns_zone_changes,
    detection.audit_log_admin_activity_detect_dns_record_modifications
  ]

  tags = merge(local.audit_log_admin_activity_dns_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_dns_zone_changes" {
  title       = "Detect DNS Zone Changes"
  description = "Detect changes to DNS zones that might disrupt domain configurations or expose infrastructure to threats."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_dns_zone_changes

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_dns_record_modifications" {
  title       = "Detect DNS Record Modifications"
  description = "Detect modifications to DNS records that might disrupt domain configurations or expose infrastructure to threats."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_dns_record_modifications

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_log_admin_activity_detect_dns_zone_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_dns_zone_changes_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'dns.googleapis.com'
      and method_name in ('dns.managedZones.patch', 'dns.managedZones.delete')
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
      and method_name ilike 'google.cloud.dns.v%.ChangeResourceRecordSet'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}