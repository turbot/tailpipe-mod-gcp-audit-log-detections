locals {
  mitre_attack_v161_ta0001_t1190_common_tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    mitre_attack_technique_id = "T1190"
  })
}

benchmark "mitre_attack_v161_ta0001_t1190" {
  title         = "T1190 Exploit Public-Facing Application"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1190.md")
  children = [
    detection.access_context_manager_level_deleted,
    detection.access_context_manager_policy_deleted,
    detection.apigee_security_action_disabled,
    detection.compute_firewall_rule_deleted,
    detection.compute_full_network_traffic_packet_deleted,
    detection.compute_full_network_traffic_packet_updated,
    detection.compute_instance_with_public_network_interface,
    detection.compute_public_ip_address_created,
    detection.compute_vpn_tunnel_deleted,
    detection.dns_record_updated,
    detection.storage_bucket_publicly_accessible,
  ]

  tags = local.mitre_attack_v161_ta0001_t1190_common_tags
}
