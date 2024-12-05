locals {
  audit_log_admin_activity_pubsub_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "Pub/Sub"
  })

  audit_log_admin_activity_detect_pubsub_subscription_creation_updates_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_pubsub_topic_creation_updates_sql_columns        = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_pubsub_topic_deletion_updates_sql_columns        = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_pubsub_subscription_deletion_updates_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

detection_benchmark "audit_log_admin_activity_pubsub_detections" {
  title       = "Admin Activity Pub/Sub Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Pubsub Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_pubsub_subscription_creation_updates,
    detection.audit_log_admin_activity_detect_pubsub_topic_creation_updates,
    detection.audit_log_admin_activity_detect_pubsub_topic_deletion_updates,
    detection.audit_log_admin_activity_detect_pubsub_subscription_deletion_updates,
  ]

  tags = merge(local.audit_log_admin_activity_pubsub_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_pubsub_subscription_creation_updates" {
  title       = "Detect Pub/Sub Subscription Creation Updates"
  description = "Detect the creation of Pub/Sub subscriptions that might indicate unauthorized access attempts or potential data exposure."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_pubsub_subscription_creation_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_pubsub_topic_creation_updates" {
  title       = "Detect Pub/Sub Topic Creation Updates"
  description = "Detect the creation of Pub/Sub topics that might indicate unauthorized access attempts or potential data exposure."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_pubsub_topic_creation_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_pubsub_topic_deletion_updates" {
  title       = "Detect Pub/Sub Topic Deletion Updates"
  description = "Detect the deletion of Pub/Sub topics that might disrupt messaging configurations or indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_pubsub_topic_deletion_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_pubsub_subscription_deletion_updates" {
  title       = "Detect Pub/Sub Subscription Deletion Updates"
  description = "Detect the deletion of Pub/Sub subscriptions that might disrupt messaging configurations or indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_pubsub_subscription_deletion_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "audit_log_admin_activity_detect_pubsub_subscription_creation_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_pubsub_subscription_creation_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'pubsub.googleapis.com'
      and method_name like 'google.pubsub.v%.Subscriber.CreateSubscription'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_pubsub_topic_creation_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_pubsub_topic_creation_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'pubsub.googleapis.com'
      and method_name like 'google.pubsub.v%.Publisher.CreateTopic'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_pubsub_topic_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_pubsub_topic_deletion_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'pubsub.googleapis.com'
      and method_name like 'google.pubsub.v%.Publisher.DeleteTopic'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_pubsub_subscription_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_pubsub_subscription_deletion_updates_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'pubsub.googleapis.com'
      and method_name like 'google.pubsub.v%.Subscriber.DeleteSubscription'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
