locals {
  mitre_v161_ta0001_t1190_common_tags = merge(local.mitre_v161_ta0001_common_tags, {
    mitre_technique_id = "T1190"
  })
}

benchmark "mitre_v161_ta0001_t1190" {
  title         = "T1190 Exploit Public-Facing Application"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0001_t1190.md")
  children = [
    detection.audit_logs_detect_access_level_deletions,
    detection.audit_logs_detect_access_policy_deletions,
    detection.audit_logs_detect_access_zone_deletions,
    detection.audit_logs_detect_api_access_to_vulnerable_services,
    detection.audit_logs_detect_compute_firewall_rule_deletion_updates,
    detection.audit_logs_detect_compute_instances_with_public_network_interfaces,
    detection.audit_logs_detect_dns_record_modifications,
    detection.audit_logs_detect_full_network_traffic_packet_deletions,
    detection.audit_logs_detect_full_network_traffic_packet_modifications,
    detection.audit_logs_detect_kubernetes_cluster_with_public_endpoint,
    detection.audit_logs_detect_public_ip_address_creation,
    detection.audit_logs_detect_storage_bucket_publicly_accessible,
    detection.audit_logs_detect_vpn_tunnel_deletions,
  ]

  tags = local.mitre_v161_ta0001_t1190_common_tags
}
