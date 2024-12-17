locals {
  mitre_v151_ta0001_t1190_common_tags = merge(local.mitre_v151_ta0001_common_tags, {
    mitre_technique_id = "T1190"
  })
}

benchmark "mitre_v151_ta0001_t1190" {
  title         = "T1190 Exploit Public-Facing Application"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0001_t1190.md")
  children = [
    detection.audit_log_admin_activity_detect_storage_bucket_publicly_accessible,
    detection.audit_log_admin_activity_detect_compute_instances_with_public_network_interfaces,
    detection.audit_log_admin_activity_detect_dns_record_modifications,
    detection.audit_log_admin_activity_detect_compute_firewall_rule_deletion_updates,
    detection.audit_log_admin_activity_detect_api_access_to_vulnerable_services,
    detection.audit_log_admin_activity_detect_kubernetes_cluster_with_public_endpoint,
    detection.audit_log_admin_activity_detect_public_ip_address_creation,
    detection.audit_log_admin_activity_detect_access_policy_deletions,
    detection.audit_log_admin_activity_detect_access_zone_deletions,
    detection.audit_log_admin_activity_detect_access_level_deletions,
    detection.audit_log_admin_activity_detect_vpn_tunnel_deletions,
    detection.audit_log_admin_activity_detect_full_network_traffic_packet_deletions,
    detection.audit_log_admin_activity_detect_full_network_traffic_packet_modifications
  ]

  tags = local.mitre_v151_ta0001_t1190_common_tags
}
