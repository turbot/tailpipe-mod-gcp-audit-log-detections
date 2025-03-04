locals {
  mitre_attack_v161_ta0004_t1078_common_tags = merge(local.mitre_attack_v161_ta0004_common_tags, {
    mitre_attack_technique_id = "T1078"
  })
}

benchmark "mitre_attack_v161_ta0004_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1078.md")
  children = [
    detection.access_context_manager_access_level_deleted,
    detection.access_context_manager_policy_deleted,
    detection.compute_disk_iam_policy_set,
    detection.compute_image_iam_policy_set,
    detection.compute_snapshot_iam_policy_set,
    detection.compute_vpn_tunnel_deleted,
    detection.dns_record_set_deleted,
    detection.dns_record_set_updated,
    detection.dns_managed_zone_deleted,
    detection.dns_managed_zone_updated,
    detection.logging_bucket_deleted,
    detection.storage_bucket_iam_permission_set,
  ]

  tags = local.mitre_attack_v161_ta0004_t1078_common_tags
}
