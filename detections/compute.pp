locals {
  compute_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/Compute"
  })

}

benchmark "compute_detections" {
  title       = "Compute Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Compute events."
  type        = "detection"
  children = [
    detection.compute_disk_iam_policy_set,
    detection.compute_firewall_rule_deleted,
    detection.compute_full_network_traffic_packet_deleted,
    detection.compute_full_network_traffic_packet_updated,
    detection.compute_image_iam_policy_set,
    detection.compute_instance_with_public_network_interface,
    detection.compute_public_ip_address_created,
    detection.compute_snapshot_iam_policy_set,
    detection.compute_vpc_flow_logs_disabled,
    detection.compute_vpc_network_shared_to_external_project,
    detection.compute_vpn_tunnel_deleted,
  ]

  tags = merge(local.compute_common_tags, {
    type = "Benchmark"
  })
}

detection "compute_vpn_tunnel_deleted" {
  title           = "VPN Tunnel Deleted"
  description     = "Detect when a VPN tunnel is deleted to check for potential disruptions to secure network connections or unauthorized access attempts that may expose resources to threats."
  documentation   = file("./detections/docs/compute_vpn_tunnel_deleted.md")
  severity        = "medium"
  query           = query.compute_vpn_tunnel_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "compute_firewall_rule_deleted" {
  title           = "Compute Firewall Rule Deleted"
  description     = "Detect when a Compute firewall rule is deleted to check for risks of exposing resources to unauthorized access or reducing the overall network security posture."
  documentation   = file("./detections/docs/compute_firewall_rule_deleted.md")
  severity        = "high"
  query           = query.compute_firewall_rule_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "compute_full_network_traffic_packet_deleted" {
  title           = "Full Network Traffic Packet Deleted"
  description     = "Detect when full network traffic packet deleted to check for risks of losing visibility into network traffic monitoring, which may indicate malicious intent or unauthorized activity."
  documentation   = file("./detections/docs/compute_full_network_traffic_packet_deleted.md")
  severity        = "high"
  query           = query.compute_full_network_traffic_packet_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "compute_full_network_traffic_packet_updated" {
  title           = "Full Network Traffic Packet Updated"
  description     = "Detect when full network traffic packet updated to check for risks of tampered network traffic monitoring configurations that could reduce visibility or enable data exfiltration."
  documentation   = file("./detections/docs/compute_full_network_traffic_packet_updated.md")
  severity        = "medium"
  query           = query.compute_full_network_traffic_packet_updated
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "compute_image_iam_policy_set" {
  title           = "Compute Image IAM Policy Set"
  description     = "Detect when a Compute image IAM policy is set to check for potential unauthorized access attempts or misconfigurations that might expose sensitive resources."
  documentation   = file("./detections/docs/compute_image_iam_policy_set.md")
  severity        = "medium"
  query           = query.compute_image_iam_policy_set
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "compute_disk_iam_policy_set" {
  title           = "Compute Disk IAM Policy Set"
  description     = "Detect when a Compute disk IAM policy is set to check for risks of unauthorized access to disk resources or data exposure due to misconfigured permissions."
  documentation   = file("./detections/docs/compute_disk_iam_policy_set.md")
  severity        = "medium"
  query           = query.compute_disk_iam_policy_set
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "compute_snapshot_iam_policy_set" {
  title           = "Compute Snapshot IAM Policy Set"
  description     = "Detect when a Compute snapshot IAM policy is set to check for potential data exposure or unauthorized access attempts."
  documentation   = file("./detections/docs/compute_snapshot_iam_policy_set.md")
  severity        = "medium"
  query           = query.compute_snapshot_iam_policy_set
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "compute_instance_with_public_network_interface" {
  title           = "Compute Instance with Public Network Interface"
  description     = "Detect when a Compute instance is configured with a public network interface to check for risks of exposing resources to unauthorized access or potential data breaches."
  documentation   = file("./detections/docs/compute_instance_with_public_network_interface.md")
  severity        = "high"
  query           = query.compute_instance_with_public_network_interface
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "compute_public_ip_address_created" {
  title           = "Compute Public IP Address Created"
  description     = "Detect when a Compute public IP address is created to check for potential exposure of resources to external threats or unauthorized access."
  documentation   = file("./detections/docs/compute_public_ip_address_created.md")
  severity        = "high"
  query           = query.compute_public_ip_address_created
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "compute_vpc_network_shared_to_external_project" {
  title           = "Compute VPC Network Shared to External Project"
  description     = "Detect when a Compute VPC network is shared with an external project to check for risks of exposing resources to unauthorized access or external threats."
  documentation   = file("./detections/docs/compute_vpc_network_shared_to_external_project.md")
  severity        = "high"
  query           = query.compute_vpc_network_shared_to_external_project
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1548"
  })
}

detection "compute_vpc_flow_logs_disabled" {
  title           = "Compute VPC Flow Logs Disabled"
  description     = "Detect when Compute VPC flow logs are disabled to check for risks of losing visibility into network traffic monitoring, which could lead to undetected malicious activity."
  documentation   = file("./detections/docs/compute_vpc_flow_logs_disabled.md")
  severity        = "medium"
  query           = query.compute_vpc_flow_logs_disabled
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

query "compute_firewall_rule_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike '%.compute.firewalls.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "compute_vpn_tunnel_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike '%.compute.vpntunnels.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "compute_full_network_traffic_packet_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike '%.compute.packetmirrorings.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "compute_full_network_traffic_packet_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike '%.compute.packetmirrorings.patch'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "compute_image_iam_policy_set" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike '%.compute.images.setiampolicy'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "compute_disk_iam_policy_set" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike '%.compute.disks.setiampolicy'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "compute_snapshot_iam_policy_set" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike '%.compute.snapshots.setiampolicy'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
// testing is needed event exist in the bucket
query "compute_instance_with_public_network_interface" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      (method_name ilike '%.compute.instances.insert' or method_name ilike '%.compute.instances.update')
      ${local.detection_sql_where_conditions}
      and exists (
        select *
        from unnest(
        cast(json_extract(request, '$.networkInterfaces[*].accessConfigs[*].name') as json[])
        ) as access_type
        where (access_type::varchar ilike '%nat%' or access_type::varchar ilike '%external%')
      )
    order by
      timestamp desc;
  EOQ
}

query "compute_public_ip_address_created" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike '%.compute.addresses.insert'
      and (request ->> 'networkTier') is not null
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "compute_vpc_network_shared_to_external_project" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike '%.compute.projects.enablexpnresource'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "compute_vpc_flow_logs_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike '%.compute.subnetworks.patch'
      and request.enableFlowLogs = 'false'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}