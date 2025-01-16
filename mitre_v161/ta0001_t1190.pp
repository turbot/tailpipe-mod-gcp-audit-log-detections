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
    detection.detect_access_context_manager_level_deletions,
    detection.detect_access_context_manager_policy_deletions,
    detection.detect_access_context_manager_zone_deletions,
    detection.detect_apigee_api_access_to_vulnerable_services,
    detection.detect_compute_firewall_rule_deletions,
    detection.detect_compute_instances_with_public_network_interfaces,
    detection.detect_dns_record_modifications,
    detection.detect_full_network_traffic_packet_deletions,
    detection.detect_full_network_traffic_packet_modifications,
    detection.detect_kubernetes_clusters_with_public_endpoints,
    detection.detect_public_ip_address_creations,
    detection.detect_storage_buckets_publicly_accessible,
    detection.detect_vpn_tunnel_deletions,
  ]

  tags = local.mitre_v161_ta0001_t1190_common_tags
}
