mod "gcp_audit_log_detections" {
  # hub metadata
  title         = "GCP Audit Log Detections"
  description   = "Run detections and view dashboards for your GCP audit logs to monitor and analyze activity across your GCP projects using Powerpipe and Tailpipe."
  color         = "#ea4335"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/gcp-audit-log-detections.svg"
  categories    = ["dashboard", "detections", "gcp", "public cloud"]
  database      = var.database

  opengraph {
    title       = "Powerpipe Mod for AWS CloudTrail Log Detections"
    description = "Run detections and view dashboards for your GCP audit logs to monitor and analyze activity across your GCP projects using Powerpipe and Tailpipe."
    image       = "/images/mods/turbot/gcp-audit-log-detections-social-graphic.png"
  }
}
