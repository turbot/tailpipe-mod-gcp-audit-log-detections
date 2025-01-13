locals {
  mitre_v151_ta0004_t1078_common_tags = merge(local.mitre_v151_ta0004_common_tags, {
    mitre_technique_id = "T1078"
  })
}

benchmark "mitre_v151_ta0004_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0004_t1078.md")
  children = [
    detection.audit_logs_detect_access_level_deletions,
    detection.audit_logs_detect_access_policy_deletions,
    detection.audit_logs_detect_access_zone_deletions,
    detection.audit_logs_detect_compute_disks_set_iam_policy,
    detection.audit_logs_detect_compute_images_set_iam_policy,
    detection.audit_logs_detect_compute_snapshots_set_iam_policy,
    detection.audit_logs_detect_dns_record_deletions,
    detection.audit_logs_detect_dns_record_modifications,
    detection.audit_logs_detect_dns_zone_deletions,
    detection.audit_logs_detect_dns_zone_modifications,
    detection.audit_logs_detect_full_network_traffic_packet_deletions,
    detection.audit_logs_detect_full_network_traffic_packet_modifications,
    detection.audit_logs_detect_kubernetes_admission_webhook_config_creations,
    detection.audit_logs_detect_kubernetes_admission_webhook_config_modifications,
    detection.audit_logs_detect_kubernetes_admission_webhook_config_replaced,
    detection.audit_logs_detect_kubernetes_cronjob_deletions,
    detection.audit_logs_detect_kubernetes_cronjob_modifications,
    detection.audit_logs_detect_kubernetes_secrets_deletions,
    detection.audit_logs_detect_logging_bucket_deletions,
    detection.audit_logs_detect_storage_set_iam_policy,
    detection.audit_logs_detect_vpn_tunnel_deletions,
  ]

  tags = local.mitre_v151_ta0004_t1078_common_tags
}
