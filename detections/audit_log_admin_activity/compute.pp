locals {
  audit_log_admin_activity_compute_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/Compute"
  })
  audit_log_admin_activity_detect_vpn_tunnel_deletions_sql_columns                             = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_firewall_rule_deletion_updates_sql_columns           = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_full_network_traffic_packet_deletions_sql_columns            = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_full_network_traffic_packet_modifications_sql_columns        = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  _updates_sql_columns                                                                         = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_disks_set_iam_policy_sql_columns                     = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_snapshots_set_iam_policy_sql_columns                 = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_unauthorized_ssh_auth_os_logins_sql_columns                  = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_instances_with_public_network_interfaces_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_public_ip_address_creation_sql_columns                       = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_vpc_network_shared_to_external_project_sql_columns           = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_image_logging_disabled_sql_columns                   = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_disk_size_small_sql_columns                          = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_compute_image_os_login_disabled_sql_columns                  = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_disable_compute_vpc_flow_logs_sql_columns                    = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_compute_detections" {
  title       = "Admin Activity Compute Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Compute Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_compute_firewall_rule_deletion_updates,
    detection.audit_log_admin_activity_detect_vpn_tunnel_deletions,
    detection.audit_log_admin_activity_detect_full_network_traffic_packet_deletions,
    detection.audit_log_admin_activity_detect_full_network_traffic_packet_modifications,
    detection.audit_log_admin_activity_detect_compute_images_set_iam_policy,
    detection.audit_log_admin_activity_detect_compute_disks_set_iam_policy,
    detection.audit_log_admin_activity_detect_compute_snapshots_set_iam_policy,
    detection.audit_log_admin_activity_detect_unauthorized_ssh_auth_os_logins,
    detection.audit_log_admin_activity_detect_compute_instances_with_public_network_interfaces,
    detection.audit_log_admin_activity_detect_public_ip_address_creation,
    detection.audit_log_admin_activity_detect_vpc_network_shared_to_external_project,
    detection.audit_log_admin_activity_detect_compute_image_logging_disabled,
    detection.audit_log_admin_activity_detect_compute_disk_size_small,
    detection.audit_log_admin_activity_detect_compute_image_os_login_disabled,
    detection.audit_log_admin_activity_detect_disable_compute_vpc_flow_logs,
  ]

  tags = merge(local.audit_log_admin_activity_compute_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_vpn_tunnel_deletions" {
  title           = "Detect VPN Tunnel Deletions"
  description     = "Detect deletions of VPN tunnels, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_vpn_tunnel_deletions
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "audit_log_admin_activity_detect_compute_firewall_rule_deletion_updates" {
  title           = "Detect Firewall Rule Changes"
  description     = "Detect changes to firewall rules, ensuring visibility into modifications that may expose multiple resources to threats and enabling prompt action to maintain network security."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_compute_firewall_rule_deletion_updates
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "audit_log_admin_activity_detect_full_network_traffic_packet_deletions" {
  title           = "Detect Full Network Traffic Packet Deletions"
  description     = "Detect deletions of full network traffic packets, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_full_network_traffic_packet_deletions
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "audit_log_admin_activity_detect_full_network_traffic_packet_modifications" {
  title           = "Detect Full Network Traffic Packet Modifications"
  description     = "Detect modifications to full network traffic packets, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_full_network_traffic_packet_modifications
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0004:T1078"
  })
}

detection "audit_log_admin_activity_detect_compute_images_set_iam_policy" {
  title           = "Detect Compute Images Set IAM Policy"
  description     = "Detect updates to compute image IAM policies, providing visibility into changes that might expose multiple resources to threats or signal unauthorized access attempts, enabling timely investigation and mitigation."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_compute_images_set_iam_policy
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "audit_log_admin_activity_detect_compute_disks_set_iam_policy" {
  title           = "Detect Compute Disks Set IAM Policy"
  description     = "Detect updates to compute disk IAM policies, ensuring visibility into potential resource exposure or unauthorized access attempts, and mitigating security risks through proactive monitoring and response."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_compute_disks_set_iam_policy
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "audit_log_admin_activity_detect_compute_snapshots_set_iam_policy" {
  title           = "Detect Compute Snapshots Set IAM Policy"
  description     = "Detect updates to compute snapshot IAM policies, ensuring visibility into potential resource exposure or unauthorized access attempts, and mitigating security risks through prompt action."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_compute_snapshots_set_iam_policy
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "audit_log_admin_activity_detect_unauthorized_ssh_auth_os_logins" {
  title           = "Detect Unauthorized SSH Auth OS Logins"
  description     = "Detect unauthorized SSH authentication OS logins, providing visibility into potential security breaches and mitigating risks associated with unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_unauthorized_ssh_auth_os_logins
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "audit_log_admin_activity_detect_compute_instances_with_public_network_interfaces" {
  title           = "Detect Compute Instances with Public Network Interfaces"
  description     = "Detect compute instances with public network interfaces, ensuring visibility into exposed resources and mitigating risks of unauthorized access or data breaches."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_compute_instances_with_public_network_interfaces
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "audit_log_admin_activity_detect_public_ip_address_creation" {
  title           = "Detect Public IP Address Creations"
  description     = "Detect the creation of public IP addresses, ensuring awareness of potential resource exposure and mitigating security risks associated with unrestricted external access."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_public_ip_address_creation
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "audit_log_admin_activity_detect_vpc_network_shared_to_external_project" {
  title           = "Detect VPC Networks Shared to External Projects"
  description     = "Detect VPC networks shared to external projects, ensuring awareness of potential resource exposure and mitigating risks associated with unauthorized access or misconfigurations."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_vpc_network_shared_to_external_project
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0005:T1548"
  })
}

detection "audit_log_admin_activity_detect_compute_image_logging_disabled" {
  title           = "Detect Compute Image Logging Disabled"
  description     = "Detect compute image logging disabled, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_compute_image_logging_disabled
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "audit_log_admin_activity_detect_compute_disk_size_small" {
  title           = "Detect Compute Disk Size Small"
  description     = "Detect compute disk sizes that are too small, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_compute_disk_size_small
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "audit_log_admin_activity_detect_compute_image_os_login_disabled" {
  title           = "Detect Compute Image OS Login Disabled"
  description     = "Detect compute image OS login disabled, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_compute_image_os_login_disabled
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "audit_log_admin_activity_detect_disable_compute_vpc_flow_logs" {
  title           = "Detect Disable Compute VPC Flow Logs"
  description     = "Detect disabling of Compute VPC flow logs, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.audit_log_admin_activity_detect_disable_compute_vpc_flow_logs
  display_columns = local.audit_log_admin_activity_detection_display_columns

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
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
      and method_name ilike 'v%.compute.firewalls.delete'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_vpn_tunnel_deletions" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_vpn_tunnel_deletions_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name ilike 'google.cloud.compute.v%.vpntunnels.delete'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_full_network_traffic_packet_deletions" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_full_network_traffic_packet_deletions_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name ilike 'google.cloud.compute.v%.packetmirrorings.delete'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_full_network_traffic_packet_modifications" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_full_network_traffic_packet_modifications_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name ilike 'google.cloud.compute.v%.packetmirrorings.patch'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_compute_images_set_iam_policy" {
  sql = <<-EOQ
    select
      ${local._updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name ilike 'v%.compute.images.setiampolicy'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_compute_disks_set_iam_policy" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_compute_disks_set_iam_policy_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name ilike 'v%.compute.disks.setiampolicy'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_compute_snapshots_set_iam_policy" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_compute_snapshots_set_iam_policy_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name ilike 'v%.compute.snapshots.setiampolicy'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_unauthorized_ssh_auth_os_logins" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_unauthorized_ssh_auth_os_logins_sql_columns}
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
      and (method_name ilike 'v%.compute.instances.insert' or method_name ilike 'v%.compute.instances.update')
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
      and method_name ilike 'v%.compute.addresses.insert'
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
      and method_name ilike 'google.cloud.compute.v%.projects.enablexpnresource'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_compute_image_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_compute_image_logging_disabled_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name ilike 'v%.compute.instances.insert'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'metadata' -> 'items', '$[*]') as json[])) as item
        where json_extract(item, '$.key') = 'google-logging-enabled'
        and json_extract(item, '$.value') = 'FALSE'
      )
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_compute_disk_size_small" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_compute_disk_size_small_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name ilike 'v%.compute.instances.insert'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'disks', '$[*]') as json[])) as disk_struct(disk)
        where json_extract(disk, '$.boot') = 'true'
        and cast(json_extract(disk, '$.initializeParams.diskSizeGb') as integer) < 15
      )
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_compute_image_os_login_disabled" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_compute_image_os_login_disabled_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name ilike 'v%.compute.instances.insert'
      and exists (
        select *
        from unnest(cast(json_extract(request -> 'metadata' -> 'items', '$[*]') as json[])) as item
        where json_extract(item, '$.key') = 'enable-oslogin'
        and json_extract(item, '$.value') = 'FALSE'
      )
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_disable_compute_vpc_flow_logs" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_disable_compute_vpc_flow_logs_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'compute.googleapis.com'
      and method_name ilike 'google.cloud.compute.v%.subnetworks.patch'
      and request.enableFlowLogs = 'false'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}