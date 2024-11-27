mod "gcp_detections" {
  # hub metadata
  title         = "GCP Detections"
  description   = "Search your GCP logs for high risk actions using Tailpipe."
  color         = "#FF9900"
  #documentation = file("./docs/index.md")
  #icon          = "/images/mods/turbot/gcp.svg"
  categories    = ["gcp", "security"]
  database      = var.database

  opengraph {
    title       = "Tailpipe Mod for GCP Detections"
    description = "Search your GCP logs for high risk actions using Tailpipe."
    #image       = "/images/mods/turbot/gcp-social-graphic.png"
  }
}
