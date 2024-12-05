locals {
  audit_log_admin_activity_compute_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "Compute"
  })
  audit_log_admin_activity_detect_vpn_tunnel_changes_sql_columns                      = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_firewall_rule_changes_sql_columns           = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_full_network_traffic_packet_updates_sql_columns     = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_snapshots_insert_sql_columns                = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_images_set_iam_policy_updates_sql_columns   = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_disks_set_iam_policy_updates_sql_columns    = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_snapshot_set_iam_policy_updates_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

detection_benchmark "audit_log_admin_activity_compute_detections" {
  title       = "Admin Activity Compute Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Compute Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_compute_firewall_rule_changes,
    detection.audit_log_admin_activity_detect_vpn_tunnel_changes,
    detection.audit_log_admin_activity_detect_full_network_traffic_packet_updates,
    detection.audit_log_admin_activity_detect_compute_snapshots_insert,
    detection.audit_log_admin_activity_detect_compute_images_set_iam_policy_updates,
    detection.audit_log_admin_activity_detect_compute_disks_set_iam_policy_updates,
    detection.audit_log_admin_activity_detect_compute_snapshot_set_iam_policy_updates,
  ]

  tags = merge(local.audit_log_admin_activity_compute_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_vpn_tunnel_changes" {
  title       = "Detect VPN Tunnel Changes"
  description = "Detect changes to VPN tunnels that might compromise secure network communication or indicate unauthorized activity.”"
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_vpn_tunnel_changes

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_compute_firewall_rule_changes" {
  title       = "Detect Firewall Rule Changes"
  description = "Detect changes to firewall rules that may expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_compute_firewall_rule_changes

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "audit_log_admin_activity_detect_full_network_traffic_packet_updates" {
  title       = "Detect Full Network Traffic Packet Updates"
  description = "Detect updates to network traffic packet configurations that might reveal unauthorized monitoring or expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_full_network_traffic_packet_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_compute_snapshots_insert" {
  title       = "Detect Compute Snapshots Insert"
  description = "Detect the creation of compute snapshots that might indicate unauthorized access attempts or potential data exposure."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_compute_snapshots_insert

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_compute_images_set_iam_policy_updates" {
  title       = "Detect Compute Images Set IAM Policy Updates"
  description = "Detect updates to compute image IAM policies that might expose resources to threats or indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_compute_images_set_iam_policy_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_compute_disks_set_iam_policy_updates" {
  title       = "Detect Compute Disks Set IAM Policy Updates"
  description = "Detect updates to compute disk IAM policies that might expose resources to threats or indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_compute_disks_set_iam_policy_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_compute_snapshot_set_iam_policy_updates" {
  title       = "Detect Compute Snapshot Set IAM Policy Updates"
  description = "Detect updates to compute snapshot IAM policies that might expose resources to threats or indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_compute_snapshot_set_iam_policy_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_log_admin_activity_detect_compute_firewall_rule_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_compute_firewall_rule_changes_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name in ('v1.compute.firewalls.insert', 'v1.compute.firewalls.update', 'v1.compute.firewalls.delete')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_vpn_tunnel_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_vpn_tunnel_changes_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and (method_name like 'google.cloud.compute.v%.VpnTunnels.Patch' or method_name like 'google.cloud.compute.v%.VpnTunnels.Delete')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_full_network_traffic_packet_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_full_network_traffic_packet_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name in ('google.cloud.compute.v1.PacketMirrorings.Delete', 'google.cloud.compute.v1.PacketMirrorings.Insert', 'google.cloud.compute.v1.PacketMirrorings.Patch', 'google.cloud.compute.v1.PacketMirrorings.List', 'google.cloud.compute.v1.PacketMirrorings.AggregatedList', 'google.cloud.compute.v1.PacketMirrorings.Get')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_compute_snapshots_insert" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_compute_snapshots_insert_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name like 'v%.compute.snapshots.insert'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_compute_images_set_iam_policy_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_compute_images_set_iam_policy_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name like 'v%.compute.images.setIamPolicy'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_compute_disks_set_iam_policy_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_compute_disks_set_iam_policy_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name like 'v%.compute.disks.setIamPolicy'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_compute_snapshot_set_iam_policy_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_compute_snapshot_set_iam_policy_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name like 'v%.compute.snapshots.setIamPolicy'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
