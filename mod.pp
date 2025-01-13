mod "gcp_audit_log_detections" {
  # hub metadata
  title         = "GCP Audit Log Detections"
  description   = "Search your GCP logs for high risk actions using Tailpipe."
  color         = "#ea4335"
  #documentation = file("./docs/index.md")
  #icon          = "/images/mods/turbot/gcp.svg"
  categories    = ["dashboard", "detections", "gcp", "public cloud"]
  database      = var.database

  opengraph {
    title       = "Tailpipe Mod for GCP Audit Log Detections"
    description = "Search your GCP logs for high risk actions using Tailpipe."
    #image       = "/images/mods/turbot/gcp-social-graphic.png"
  }
}
