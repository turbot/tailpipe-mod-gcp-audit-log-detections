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
    detection.access_context_manager_level_deleted,
    detection.access_context_manager_policy_deleted,
    detection.apigee_api_accessed_vulnerable_services,
    detection.compute_firewall_rule_deleted,
    detection.compute_instance_with_public_network_interface,
    detection.detect_dns_record_modifications,
    detection.compute_full_network_traffic_packet_deleted,
    detection.compute_full_network_traffic_packet_updated,
    detection.detect_kubernetes_clusters_with_public_endpoints,
    detection.compute_public_ip_address_created,
    detection.detect_storage_buckets_publicly_accessible,
    detection.compute_vpn_tunnel_deleted,
  ]

  tags = local.mitre_v161_ta0001_t1190_common_tags
}
