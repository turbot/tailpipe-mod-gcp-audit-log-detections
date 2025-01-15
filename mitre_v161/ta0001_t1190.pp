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
    detection.detect_access_level_deletions,
    detection.detect_access_policy_deletions,
    detection.detect_access_zone_deletions,
    detection.detect_api_access_to_vulnerable_services,
    detection.detect_compute_firewall_rule_deletion_updates,
    detection.detect_compute_instances_with_public_network_interfaces,
    detection.detect_dns_record_modifications,
    detection.detect_full_network_traffic_packet_deletions,
    detection.detect_full_network_traffic_packet_modifications,
    detection.detect_kubernetes_cluster_with_public_endpoint,
    detection.detect_public_ip_address_creation,
    detection.detect_storage_bucket_publicly_accessible,
    detection.detect_vpn_tunnel_deletions,
  ]

  tags = local.mitre_v161_ta0001_t1190_common_tags
}
