locals {
  audit_log_detection_common_tags = {
    service = "GCP/AuditLogs"
  }

  audit_log_detect_unauthorized_access_attempts_sql_columns        = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_privilege_elevations_sql_columns                = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_service_account_creations_sql_columns           = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_firewall_rule_changes_sql_columns               = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_unusual_resource_consumption_sql_columns        = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_vpn_tunnel_changes_sql_columns                  = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_sql_database_changes_sql_columns                = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_dns_zone_changes_sql_columns                    = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_storage_bucket_changes_sql_columns              = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_full_network_traffic_packet_updates_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_kubernetes_secrets_modified_sql_columns         = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_service_account_disabled_or_deleted_sql_columns = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_detect_access_policy_deletion_updates_sql_columns      = replace(local.audit_log_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

detection_benchmark "audit_log_detections" {
  title       = "GCP Audit Log Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Audit Logs."
  type        = "detection"
  children = [
    detection.audit_log_detect_unauthorized_access_attempts,
    detection.audit_log_detect_privilege_elevations,
    detection.audit_log_detect_service_account_creations,
    detection.audit_log_detect_firewall_rule_changes,
    detection.audit_log_detect_unusual_resource_consumption,
    detection.audit_log_detect_vpn_tunnel_changes,
    detection.audit_log_detect_sql_database_changes,
    detection.audit_log_detect_dns_zone_changes,
    detection.audit_log_detect_storage_bucket_changes,
    detection.audit_log_detect_full_network_traffic_packet_updates,
    detection.audit_log_detect_kubernetes_secrets_modification_updates,
    detection.audit_log_detect_service_account_disabled_or_deleted,
    detection.audit_log_detect_access_policy_deletion_updates
  ]

  tags = merge(local.audit_log_detection_common_tags, {
    type = "Benchmark"
  })
}

/*
 * Detections
 */

detection "audit_log_detect_unauthorized_access_attempts" {
  title       = "Detect Unauthorized Access Attempts"
  description = "Detect failed or unauthorized access attempts to GCP resources."
  severity    = "high"
  query       = query.audit_log_detect_unauthorized_access_attempts

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1078"
  })
}

detection "audit_log_detect_privilege_elevations" {
  title       = "Detect Privilege Elevations"
  description = "Detect privilege escalations by monitoring IAM policy changes."
  severity    = "medium"
  query       = query.audit_log_detect_privilege_elevations

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1136"
  })
}

detection "audit_log_detect_service_account_creations" {
  title       = "Detect Service Account Creations"
  description = "Detect newly created service accounts that might indicate potential misuse."
  severity    = "medium"
  query       = query.audit_log_detect_service_account_creations

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = "TA0006:T1078"
  })
}

detection "audit_log_detect_firewall_rule_changes" {
  title       = "Detect Firewall Rule Changes"
  description = "Detect changes to firewall rules that may expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_detect_firewall_rule_changes

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "audit_log_detect_unusual_resource_consumption" {
  title       = "Detect Unusual Resource Consumption"
  description = "Detect spikes in resource usage, which could indicate malicious activity like mining."
  severity    = "medium"
  query       = query.audit_log_detect_unusual_resource_consumption

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1566"
  })
}

detection "audit_log_detect_vpn_tunnel_changes" {
  title       = "Detect VPN Tunnel Changes"
  description = "Detect changes to VPN tunnels that might compromise secure network communication or indicate unauthorized activity.”"
  severity    = "medium"
  query       = query.audit_log_detect_vpn_tunnel_changes

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_detect_sql_database_changes" {
  title       = "Detect SQL Database Changes"
  description = "Detect changes to SQL databases that could signal unauthorized modifications or potential security risks."
  severity    = "medium"
  query       = query.audit_log_detect_sql_database_changes

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_detect_dns_zone_changes" {
  title       = "Detect DNS Zone Changes"
  description = "Detect changes to DNS zones that might disrupt domain configurations or expose infrastructure to threats."
  severity    = "medium"
  query       = query.audit_log_detect_dns_zone_changes

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_detect_storage_bucket_changes" {
  title       = "Detect Storage Bucket Changes"
  description = "Detect changes to storage buckets that could lead to data exposure, unauthorized access, or configuration drift."
  severity    = "medium"
  query       = query.audit_log_detect_storage_bucket_changes

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_detect_full_network_traffic_packet_updates" {
  title       = "Detect Full Network Traffic Packet Updates"
  description = "Detect updates to network traffic packet configurations that might reveal unauthorized monitoring or expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_detect_full_network_traffic_packet_updates

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_detect_kubernetes_secrets_modification_updates" {
  title       = "Detect Kubernetes Secrets Modification Updates"
  description = "Detect changes to Kubernetes secrets that might compromise sensitive information or indicate unauthorized access attempts"
  severity    = "medium"
  query       = query.audit_log_detect_kubernetes_secrets_modification_updates

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_detect_service_account_disabled_or_deleted" {
  title       = "Detect Service Account Disabled or Deleted"
  description = "Detect disabled or deleted service accounts that might indicate malicious actions or disrupt resource access."
  severity    = "medium"
  query       = query.audit_log_detect_service_account_disabled_or_deleted

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_detect_access_policy_deletion_updates" {
  title       = "Detect Access Policy Deletion Updates"
  description = "Detect deletions of access policies that might disrupt security configurations or expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_detect_access_policy_deletion_updates

  tags = merge(local.audit_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}
/*
 * Queries
 */

query "audit_log_detect_unauthorized_access_attempts" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_unauthorized_access_attempts_sql_columns}
    from
      gcp_audit_log_activity
    where
      method_name = 'google.logging.v2.WriteLogEntries'
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_privilege_elevations" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_privilege_elevations_sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name = 'SetIamPolicy'
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_service_account_creations" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_service_account_creations_sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name = 'CreateServiceAccount'
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_firewall_rule_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_firewall_rule_changes_sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name in ('insert', 'update', 'delete')
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_unusual_resource_consumption" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_unusual_resource_consumption_sql_columns}
    from
      gcp_audit_log_activity
    where
      method_name = 'google.monitoring.v3.CreateTimeSeries'
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_vpn_tunnel_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect__sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name in ('google.cloud.compute.v1.VpnTunnels.Patch', 'google.cloud.compute.v1.VpnTunnels.Delete')
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_sql_database_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_sql_database_changes_sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'sqladmin.googleapis.com'
      and method_name in ('cloudsql.instances.delete', 'cloudsql.instances.patch')
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_dns_zone_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_detection_sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'dns.googleapis.com'
      and method_name in ('ddns.managedZones.patch', 'dns.managedZones.delete')
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_storage_bucket_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_detection_sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'storage.googleapis.com'
      and method_name in ('storage.buckets.update', 'storage.buckets.delete')
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_full_network_traffic_packet_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_full_network_traffic_packet_updates_sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name in ('google.cloud.compute.v1.PacketMirrorings.Delete', 'google.cloud.compute.v1.PacketMirrorings.Insert', 'google.cloud.compute.v1.PacketMirrorings.Patch', 'google.cloud.compute.v1.PacketMirrorings.List', 'google.cloud.compute.v1.PacketMirrorings.AggregatedList', 'google.cloud.compute.v1.PacketMirrorings.Get')
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_kubernetes_secrets_modification_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_kubernetes_secrets_modified_sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'k8s.io'
      and method_name in ('io.k8s.api.core.v1.secrets.delete', 'io.k8s.api.core.v1.secrets.update')
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_service_account_disabled_or_deleted" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_service_account_disabled_or_deleted_sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'iam.googleapis.com'
      and method_name in ('google.iam.admin.v1.ServiceAccounts.Delete', 'google.iam.admin.v1.ServiceAccounts.Disable')
    order by
      timestamp desc;
  EOQ
}

query "audit_log_detect_access_policy_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_detect_access_policy_deletion_updates_sql_columns}
    from
      gcp_audit_log_activity
    where
      service_name = 'accesscontextmanager.googleapis.com'
      and method_name in ('accesscontextmanager.accessPolicies.authorizedOrgsDescs.delete', 'accesscontextmanager.accessPolicies.accessZones.delete', 'accesscontextmanager.accessPolicies.accessLevels.delete', 'accesscontextmanager.accessPolicies.delete')
    order by
      timestamp desc;
  EOQ
}