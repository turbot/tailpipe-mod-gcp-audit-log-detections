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
    detection.compute_disk_with_small_size,
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
  description     = "Detect deletions of VPN tunnels, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  documentation   = file("./detections/docs/compute_vpn_tunnel_deleted.md")
  severity        = "high"
  query           = query.compute_vpn_tunnel_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "compute_firewall_rule_deleted" {
  title           = "Compute Firewall Rule Deleted"
  description     = "Detect Compute firewall rule deletions, ensuring visibility into modifications that may expose multiple resources to threats and enabling prompt action to maintain network security."
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
  description     = "Detect deletions of full network traffic packets, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  documentation   = file("./detections/docs/compute_full_network_traffic_packet_deleted.md")
  severity        = "high"
  query           = query.compute_full_network_traffic_packet_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "compute_full_network_traffic_packet_updated" {
  title           = "Full Network Traffic Packet Modified"
  description     = "Detect modifications to full network traffic packets, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  documentation   = file("./detections/docs/compute_full_network_traffic_packet_updated.md")
  severity        = "high"
  query           = query.compute_full_network_traffic_packet_updated
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "compute_image_iam_policy_set" {
  title           = "Compute Image IAM Policy Set"
  description     = "Detect updates to compute image IAM policies, providing visibility into changes that might expose multiple resources to threats or signal unauthorized access attempts, enabling timely investigation and mitigation."
  documentation   = file("./detections/docs/compute_image_iam_policy_set.md")
  severity        = "low"
  query           = query.compute_image_iam_policy_set
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "compute_disk_iam_policy_set" {
  title           = "Compute Disk IAM Policy Set"
  description     = "Detect updates to compute disk IAM policies, ensuring visibility into potential resource exposure or unauthorized access attempts, and mitigating security risks through proactive monitoring and response."
  documentation   = file("./detections/docs/compute_disk_iam_policy_set.md")
  severity        = "low"
  query           = query.compute_disk_iam_policy_set
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "compute_snapshot_iam_policy_set" {
  title           = "Compute Snapshot IAM Policy Set"
  description     = "Detect updates to compute snapshot IAM policies, ensuring visibility into potential resource exposure or unauthorized access attempts, and mitigating security risks through prompt action."
  documentation   = file("./detections/docs/compute_snapshot_iam_policy_set.md")
  severity        = "low"
  query           = query.compute_snapshot_iam_policy_set
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "compute_instance_with_public_network_interface" {
  title           = "Compute Instance with Public Network Interface"
  description     = "Detect compute instances with public network interfaces, ensuring visibility into exposed resources and mitigating risks of unauthorized access or data breaches."
  documentation   = file("./detections/docs/compute_instance_with_public_network_interface.md")
  severity        = "high"
  query           = query.compute_instance_with_public_network_interface
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "compute_public_ip_address_created" {
  title           = "Public IP Address Created"
  description     = "Detect the creation of public IP addresses, ensuring awareness of potential resource exposure and mitigating security risks associated with unrestricted external access."
  documentation   = file("./detections/docs/compute_public_ip_address_created.md")
  severity        = "high"
  query           = query.compute_public_ip_address_created
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "compute_vpc_network_shared_to_external_project" {
  title           = "VPC Network Shared to External Project"
  description     = "Detect VPC networks shared to external projects, ensuring awareness of potential resource exposure and mitigating risks associated with unauthorized access or misconfigurations."
  documentation   = file("./detections/docs/compute_vpc_network_shared_to_external_project.md")
  severity        = "high"
  query           = query.compute_vpc_network_shared_to_external_project
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1548"
  })
}

detection "compute_disk_with_small_size" {
  title           = "Compute Disk with Small Size"
  description     = "Detect compute disk sizes that are too small, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  documentation   = file("./detections/docs/compute_disk_with_small_size.md")
  severity        = "low"
  query           = query.compute_disk_with_small_size
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "compute_vpc_flow_logs_disabled" {
  title           = "Compute VPC Flow Logs Disabled"
  description     = "Detect disabling of Compute VPC flow logs, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  documentation   = file("./detections/docs/compute_vpc_flow_logs_disabled.md")
  severity        = "high"
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
      service_name = 'compute.googleapis.com'
      and method_name ilike 'v%.compute.firewalls.delete'
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
      service_name = 'compute.googleapis.com'
      and method_name ilike 'v%.compute.vpntunnels.delete'
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
      service_name = 'compute.googleapis.com'
      and method_name ilike 'google.cloud.compute.v%.packetmirrorings.delete'
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
      service_name = 'compute.googleapis.com'
      and method_name ilike 'google.cloud.compute.v%.packetmirrorings.patch'
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
      service_name = 'compute.googleapis.com'
      and method_name ilike 'v%.compute.images.setiampolicy'
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
      service_name = 'compute.googleapis.com'
      and method_name ilike 'v%.compute.disks.setiampolicy'
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
      service_name = 'compute.googleapis.com'
      and method_name ilike 'v%.compute.snapshots.setiampolicy'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "compute_instance_with_public_network_interface" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      service_name = 'compute.googleapis.com'
      and (method_name ilike '%.compute.instances.insert' or method_name ilike '%.compute.instances.update')
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
      service_name = 'compute.googleapis.com'
      and method_name ilike 'v%.compute.addresses.insert'
      and request.networkTier is not null
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
      service_name = 'compute.googleapis.com'
      and method_name ilike 'googleapis.cloud.compute.v%.projects.enablexpnresource'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "compute_disk_with_small_size" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      service_name = 'compute.googleapis.com'
      and method_name ilike '%.compute.instances.insert'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'disks', '$[*]') as json[])) as disk_struct(disk)
        where json_extract(disk, '$.boot') = 'true'
        and cast(json_extract(disk, '$.initializeParams.diskSizeGb') as integer) < 15
      )
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
      service_name = 'compute.googleapis.com'
      and method_name ilike 'google.cloud.compute.v%.subnetworks.patch'
      and request.enableFlowLogs = 'false'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}