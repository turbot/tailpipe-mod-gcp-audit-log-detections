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
    detection.compute_image_iam_policy_set,
    detection.compute_instance_with_public_network_interface,
    detection.compute_snapshot_iam_policy_set,
    detection.compute_subnetwork_flow_logs_disabled,
    detection.compute_vpn_tunnel_deleted,
  ]

  tags = merge(local.compute_common_tags, {
    type = "Benchmark"
  })
}

detection "compute_vpn_tunnel_deleted" {
  title           = "Compute VPN Tunnel Deleted"
  description     = "Detect when a VPN tunnel was deleted to check for potential disruptions to secure network connections or unauthorized access attempts that may expose resources to threats."
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
  description     = "Detect when a Compute firewall rule was deleted to check for risks of exposing resources to unauthorized access or reducing the overall network security posture."
  documentation   = file("./detections/docs/compute_firewall_rule_deleted.md")
  severity        = "high"
  query           = query.compute_firewall_rule_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0005:T1562"
  })
}

detection "compute_image_iam_policy_set" {
  title           = "Compute Image IAM Policy Set"
  description     = "Detect when a Compute image IAM policy was set to check for potential unauthorized access attempts or misconfigurations that might expose sensitive resources."
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
  description     = "Detect when a Compute disk IAM policy was set to check for risks of unauthorized access to disk resources or data exposure due to misconfigured permissions."
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
  description     = "Detect when a Compute snapshot IAM policy was set to check for potential data exposure or unauthorized access attempts."
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
  description     = "Detect when a Compute instance was configured with a public network interface to check for risks of exposing resources to unauthorized access or potential data breaches."
  documentation   = file("./detections/docs/compute_instance_with_public_network_interface.md")
  severity        = "high"
  query           = query.compute_instance_with_public_network_interface
  display_columns = local.detection_display_columns

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

detection "compute_subnetwork_flow_logs_disabled" {
  title           = "Compute Subnetwork Flow Logs Disabled"
  description     = "Detect when Compute Subnetwork flow logs were disabled to check for risks of losing visibility into network traffic monitoring, which could lead to undetected malicious activity."
  documentation   = file("./detections/docs/compute_subnetwork_flow_logs_disabled.md")
  severity        = "medium"
  query           = query.compute_subnetwork_flow_logs_disabled
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

query "compute_instance_with_public_network_interface" {
  sql = <<-EOQ
    with network_if as (
      select
          *,
        unnest(from_json(request -> 'networkInterfaces', '["json"]')) as netif
      from
        gcp_audit_log
      where
        (
        method_name ilike '%.compute.instances.insert'
        or method_name ilike '%.compute.instances.update'
        )
      ),
      access_cfg as (
        select
          *,
          unnest(from_json(netif -> 'accessConfigs', '["json"]')) as ac
        from network_if
      )
      select
        ${local.detection_sql_resource_column_resource_name}
        ac
      from
        access_cfg
      where
        (
          (ac ->> 'name') ilike '%nat%'
          or (ac ->> 'name') ilike '%external%'
        )
        ${local.detection_sql_where_conditions}
      order by
        timestamp desc;
  EOQ
}

query "compute_subnetwork_flow_logs_disabled" {
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