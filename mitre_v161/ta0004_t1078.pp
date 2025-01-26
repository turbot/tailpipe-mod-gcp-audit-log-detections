locals {
  mitre_v161_ta0004_t1078_common_tags = merge(local.mitre_v161_ta0004_common_tags, {
    mitre_technique_id = "T1078"
  })
}

benchmark "mitre_v161_ta0004_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0004_t1078.md")
  children = [
    detection.access_context_manager_level_deleted,
    detection.access_context_manager_policy_deleted,
    detection.compute_disk_iam_policy_set,
    detection.compute_image_iam_policy_set,
    detection.compute_snapshot_iam_policy_set,
    detection.detect_dns_record_deletions,
    detection.detect_dns_record_modifications,
    detection.detect_dns_zone_deletions,
    detection.detect_dns_zone_modifications,
    detection.compute_full_network_traffic_packet_deleted,
    detection.compute_full_network_traffic_packet_updated,
    detection.detect_kubernetes_admission_webhook_config_creations,
    detection.detect_kubernetes_admission_webhook_config_modifications,
    detection.detect_kubernetes_admission_webhook_configs_replaced,
    detection.detect_kubernetes_cronjob_deletions,
    detection.detect_kubernetes_cronjob_modifications,
    detection.detect_kubernetes_secrets_deletions,
    detection.detect_logging_bucket_deletions,
    detection.detect_storage_set_iam_policies,
    detection.compute_vpn_tunnel_deleted,
  ]

  tags = local.mitre_v161_ta0004_t1078_common_tags
}
