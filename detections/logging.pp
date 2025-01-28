locals {
  logging_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/Logging"
  })
}

benchmark "logging_detections" {
  title       = "Logging Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Logging events."
  type        = "detection"
  children = [
    detection.logging_bucket_deleted,
    detection.logging_sink_deleted,
    detection.logging_unauthorized_access_attempt,
  ]

  tags = merge(local.logging_common_tags, {
    type = "Benchmark"
  })
}

detection "logging_unauthorized_access_attempt" {
  title           = "Logging Unauthorized Access Attempt"
  description     = "Detect when a logging unauthorized access attempt was made to GCP resources, potentially indicating security threats or compromised credentials. Monitoring such attempts helps ensure prompt identification and mitigation of risks to the environment and protects resources from unauthorized actions."
  documentation   = file("./detections/docs/logging_unauthorized_access_attempt.md")
  severity        = "high"
  query           = query.logging_unauthorized_access_attempt
  display_columns = local.detection_display_columns

  tags = merge(local.logging_common_tags, {
    mitre_attack_ids = "TA0006:T1078"
  })
}

detection "logging_sink_deleted" {
  title           = "Logging Sink Deleted"
  description     = "Detect when a logging sink was deleted, potentially disrupting logging configurations or indicating unauthorized access attempts. Monitoring logging sink deletions helps ensure logging integrity and enables the timely identification of suspicious activities."
  documentation   = file("./detections/docs/logging_sink_deleted.md")
  severity        = "high"
  query           = query.logging_sink_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.logging_common_tags, {
    mitre_attack_ids = "TA0005:T1211"
  })
}

detection "logging_bucket_deleted" {
  title           = "Logging Bucket Deleted"
  description     = "Detect when a logging bucket was deleted, potentially disrupting logging configurations or indicating unauthorized access attempts. Monitoring logging bucket deletions helps maintain logging integrity and provides visibility into suspicious activities."
  documentation   = file("./detections/docs/logging_bucket_deleted.md")
  severity        = "high"
  query           = query.logging_bucket_deleted
  display_columns = local.detection_display_columns

  tags = merge(local.logging_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

query "logging_unauthorized_access_attempt" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.logging.v%.loggingserviceV%.writelogentriesrequest'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "logging_sink_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.logging.v%.configservicev%.deletesink'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "logging_bucket_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_resource_name}
    from
      gcp_audit_log
    where
      method_name ilike 'google.logging.v%.configservicev%.deletebucket'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}