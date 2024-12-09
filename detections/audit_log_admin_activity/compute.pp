locals {
  audit_log_admin_activity_compute_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/Compute"
  })
  audit_log_admin_activity_detect_vpn_tunnel_changes_sql_columns                               = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_firewall_rule_deletion_updates_sql_columns           = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_full_network_traffic_packet_updates_sql_columns              = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_images_set_iam_policy_updates_sql_columns            = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_disks_set_iam_policy_updates_sql_columns             = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_snapshot_set_iam_policy_updates_sql_columns          = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_unauthorized_ssh_auth_os_login_updates_sql_columns           = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_instances_with_public_network_interfaces_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_public_ip_address_creation_sql_columns                       = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_vpc_network_shared_to_external_project_sql_columns         = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_compute_detections" {
  title       = "Admin Activity Compute Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Compute Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_compute_firewall_rule_deletion_updates,
    detection.audit_log_admin_activity_detect_vpn_tunnel_changes,
    detection.audit_log_admin_activity_detect_full_network_traffic_packet_updates,
    detection.audit_log_admin_activity_detect_compute_images_set_iam_policy_updates,
    detection.audit_log_admin_activity_detect_compute_disks_set_iam_policy_updates,
    detection.audit_log_admin_activity_detect_compute_snapshot_set_iam_policy_updates,
    detection.audit_log_admin_activity_detect_unauthorized_ssh_auth_os_login_updates,
    detection.audit_log_admin_activity_detect_compute_instances_with_public_network_interfaces,
    detection.audit_log_admin_activity_detect_public_ip_address_creation,
    detection.audit_log_admin_activity_detect_vpc_network_shared_to_external_project,
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

detection "audit_log_admin_activity_detect_compute_firewall_rule_deletion_updates" {
  title       = "Detect Firewall Rule Changes"
  description = "Detect changes to firewall rules that may expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_compute_firewall_rule_deletion_updates

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

detection "audit_log_admin_activity_detect_unauthorized_ssh_auth_os_login_updates" {
  title       = "Detect Unauthorized SSH Auth OS Login Updates"
  description = "Detect unauthorized SSH authentication attempts that might indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_unauthorized_ssh_auth_os_login_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_compute_instances_with_public_network_interfaces" {
  title       = "Detect Compute Instances with Public Network Interfaces"
  description = "Detect compute instances with public network interfaces that might expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_compute_instances_with_public_network_interfaces

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "audit_log_admin_activity_detect_public_ip_address_creation" {
  title       = "Detect Public IP Address Creation"
  description = "Detect the creation of public IP addresses that might expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_public_ip_address_creation

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "audit_log_admin_activity_detect_vpc_network_shared_to_external_project" {
  title       = "Detect VPC Network Shared to External Project"
  description = "Detect VPC networks shared to external projects that might expose resources to threats."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_vpc_network_shared_to_external_project

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "audit_log_admin_activity_detect_compute_firewall_rule_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_compute_firewall_rule_deletion_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name like 'v%.compute.firewalls.delete'
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
      and (method_name like 'google.cloud.compute.v%.PacketMirrorings.Delete' or method_name like 'google.cloud.compute.v%.PacketMirrorings.Insert' or method_name like 'google.cloud.compute.v%.PacketMirrorings.Patch')
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

query "audit_log_admin_activity_detect_unauthorized_ssh_auth_os_login_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_unauthorized_ssh_auth_os_login_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      method_name = 'compute.instances.osLogin.authenticate'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
// TODO: Need to test this query
query "audit_log_admin_activity_detect_compute_instances_with_public_network_interfaces" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_compute_instances_with_public_network_interfaces_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and (method_name like 'v%.compute.instances.insert' or method_name like 'v%.compute.instances.update')
      and request.resource.networkInterfaces.accessConfigs.natIP is not null
      ${local.audit_log_admin_activity_detection_where_conditions}
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'networkinterfaces', '$[*].accessconfigs[*].type') as varchar[])) as access_type
        where access_type = 'one_to_one_nat'
      )
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_public_ip_address_creation" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_public_ip_address_creation_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name like 'v%.compute.addresses.insert'
      and cast(json_extract(request, '$.addressType') as varchar) = 'EXTERNAL'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_vpc_network_shared_to_external_project" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_vpc_network_shared_to_external_project_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name like 'google.cloud.compute.v%.Projects.EnableXpnResource'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
