locals {
  compute_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/Compute"
  })
  detect_vpn_tunnel_deletions_sql_columns                                         = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_compute_firewall_rule_deletion_updates_sql_columns                       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_full_network_traffic_packet_deletions_sql_columns                        = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_full_network_traffic_packet_modifications_sql_columns                    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_compute_images_set_iam_policy_sql_columns                                = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_compute_disks_set_iam_policy_sql_columns                                 = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_compute_snapshots_set_iam_policy_sql_columns                             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_compute_instances_with_public_network_interfaces_sql_columns             = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_public_ip_address_creation_sql_columns                                   = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_vpc_network_shared_to_external_project_sql_columns                       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_compute_disk_size_small_sql_columns                                      = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_disable_compute_vpc_flow_logs_sql_columns                                = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_compute_instances_with_metadata_startup_script_modifications_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "compute_detections" {
  title       = "Compute Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Compute events."
  type        = "detection"
  children = [
    detection.detect_compute_firewall_rule_deletion_updates,
    detection.detect_vpn_tunnel_deletions,
    detection.detect_full_network_traffic_packet_deletions,
    detection.detect_full_network_traffic_packet_modifications,
    detection.detect_compute_images_set_iam_policy,
    detection.detect_compute_disks_set_iam_policy,
    detection.detect_compute_snapshots_set_iam_policy,
    detection.detect_compute_instances_with_public_network_interfaces,
    detection.detect_public_ip_address_creation,
    detection.detect_vpc_network_shared_to_external_project,
    detection.detect_compute_disk_size_small,
    detection.detect_disable_compute_vpc_flow_logs,
    detection.detect_compute_instances_with_metadata_startup_script_modifications,
  ]

  tags = merge(local.compute_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_vpn_tunnel_deletions" {
  title           = "Detect Compute VPN Tunnel Deletions"
  description     = "Detect deletions of VPN tunnels, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_vpn_tunnel_deletions
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "detect_compute_firewall_rule_deletion_updates" {
  title           = "Detect Compute Firewall Rule Deletion Updates"
  description     = "Detect updates to firewall rules, ensuring visibility into modifications that may expose multiple resources to threats and enabling prompt action to maintain network security."
  severity        = "medium"
  query           = query.detect_compute_firewall_rule_deletion_updates
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "detect_full_network_traffic_packet_deletions" {
  title           = "Detect Compute Full Network Traffic Packet Deletions"
  description     = "Detect deletions of full network traffic packets, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_full_network_traffic_packet_deletions
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "detect_full_network_traffic_packet_modifications" {
  title           = "Detect Compute Full Network Traffic Packet Modifications"
  description     = "Detect modifications to full network traffic packets, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_full_network_traffic_packet_modifications
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "detect_compute_images_set_iam_policy" {
  title           = "Detect Compute Images Set IAM Policy"
  description     = "Detect updates to compute image IAM policies, providing visibility into changes that might expose multiple resources to threats or signal unauthorized access attempts, enabling timely investigation and mitigation."
  severity        = "medium"
  query           = query.detect_compute_images_set_iam_policy
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "detect_compute_disks_set_iam_policy" {
  title           = "Detect Compute Disks Set IAM Policy"
  description     = "Detect updates to compute disk IAM policies, ensuring visibility into potential resource exposure or unauthorized access attempts, and mitigating security risks through proactive monitoring and response."
  severity        = "medium"
  query           = query.detect_compute_disks_set_iam_policy
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "detect_compute_snapshots_set_iam_policy" {
  title           = "Detect Compute Snapshots Set IAM Policy"
  description     = "Detect updates to compute snapshot IAM policies, ensuring visibility into potential resource exposure or unauthorized access attempts, and mitigating security risks through prompt action."
  severity        = "medium"
  query           = query.detect_compute_snapshots_set_iam_policy
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "detect_compute_instances_with_public_network_interfaces" {
  title           = "Detect Compute Instances with Public Network Interfaces"
  description     = "Detect compute instances with public network interfaces, ensuring visibility into exposed resources and mitigating risks of unauthorized access or data breaches."
  severity        = "medium"
  query           = query.detect_compute_instances_with_public_network_interfaces
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "detect_public_ip_address_creation" {
  title           = "Detect Public IP Address Creations"
  description     = "Detect the creation of public IP addresses, ensuring awareness of potential resource exposure and mitigating security risks associated with unrestricted external access."
  severity        = "medium"
  query           = query.detect_public_ip_address_creation
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "detect_vpc_network_shared_to_external_project" {
  title           = "Detect VPC Networks Shared to External Projects"
  description     = "Detect VPC networks shared to external projects, ensuring awareness of potential resource exposure and mitigating risks associated with unauthorized access or misconfigurations."
  severity        = "medium"
  query           = query.detect_vpc_network_shared_to_external_project
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1548"
  })
}

detection "detect_compute_disk_size_small" {
  title           = "Detect Compute Disk Size Small"
  description     = "Detect compute disk sizes that are too small, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_compute_disk_size_small
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "detect_disable_compute_vpc_flow_logs" {
  title           = "Detect Disable Compute VPC Flow Logs"
  description     = "Detect disabling of Compute VPC flow logs, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_disable_compute_vpc_flow_logs
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

detection "detect_compute_instances_with_metadata_startup_script_modifications" {
  title           = "Detect Compute Instances with Metadata Startup Script Modifications"
  description     = "Detect modifications to Compute Engine instance metadata to check for unauthorized changes, such as malicious startup scripts that could deface hosted services, disrupt operations, or introduce vulnerabilities."
  severity        = "medium"
  query           = query.detect_compute_instances_with_metadata_startup_script_modifications
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0040:T1491"
  })
}

query "detect_compute_instances_with_metadata_startup_script_modifications" {
  sql = <<-EOQ
    select
      ${local.detect_compute_instances_with_metadata_startup_script_modifications_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'compute.googleapis.com'
      and (method_name ilike 'v1.compute.instances.setMetadata')
      and (json_extract_string(request, '$.Metadata Keys Added') = '["startup-script"]'
        OR json_extract_string(request, '$.Metadata Keys Modified') = '["startup-script"]' OR json_extract_string(request, '$.Metadata Keys Deleted') = '["startup-script"]')
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

// tested
query "detect_compute_firewall_rule_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.detect_compute_firewall_rule_deletion_updates_sql_columns}
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

query "detect_vpn_tunnel_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_vpn_tunnel_deletions_sql_columns}
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

query "detect_full_network_traffic_packet_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_full_network_traffic_packet_deletions_sql_columns}
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

query "detect_full_network_traffic_packet_modifications" {
  sql = <<-EOQ
    select
      ${local.detect_full_network_traffic_packet_modifications_sql_columns}
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

query "detect_compute_images_set_iam_policy" {
  sql = <<-EOQ
    select
      ${local.detect_compute_images_set_iam_policy_sql_columns}
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

query "detect_compute_disks_set_iam_policy" {
  sql = <<-EOQ
    select
      ${local.detect_compute_disks_set_iam_policy_sql_columns}
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

query "detect_compute_snapshots_set_iam_policy" {
  sql = <<-EOQ
    select
      ${local.detect_compute_snapshots_set_iam_policy_sql_columns}
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

query "detect_compute_instances_with_public_network_interfaces" {
  sql = <<-EOQ
    select
      ${local.detect_compute_instances_with_public_network_interfaces_sql_columns}
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

query "detect_public_ip_address_creation" {
  sql = <<-EOQ
    select
      ${local.detect_public_ip_address_creation_sql_columns}
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

query "detect_vpc_network_shared_to_external_project" {
  sql = <<-EOQ
    select
      ${local.detect_vpc_network_shared_to_external_project_sql_columns}
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

// testing needed
query "detect_compute_disk_size_small" {
  sql = <<-EOQ
    select
      ${local.detect_compute_disk_size_small_sql_columns}
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

// testing needed
query "detect_disable_compute_vpc_flow_logs" {
  sql = <<-EOQ
    select
      ${local.detect_disable_compute_vpc_flow_logs_sql_columns}
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