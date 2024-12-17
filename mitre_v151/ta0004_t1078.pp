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
    detection.audit_log_admin_activity_detect_access_policy_deletions,
    detection.audit_log_admin_activity_detect_access_zone_deletions,
    detection.audit_log_admin_activity_detect_access_level_deletions,
    detection.audit_log_admin_activity_detect_vpn_tunnel_deletions,
    detection.audit_log_admin_activity_detect_full_network_traffic_packet_deletions,
    detection.audit_log_admin_activity_detect_full_network_traffic_packet_modifications,
    detection.audit_log_admin_activity_detect_compute_images_set_iam_policy,
    detection.audit_log_admin_activity_detect_compute_disks_set_iam_policy,
    detection.audit_log_admin_activity_detect_compute_snapshots_set_iam_policy,
    detection.audit_log_admin_activity_detect_unauthorized_ssh_auth_os_logins,
  ]

  tags = local.mitre_v151_ta0001_t1190_common_tags
}
