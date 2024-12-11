locals {
  audit_log_admin_activity_kubernetes_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "GCP/Kubernetes"
  })

  audit_log_admin_activity_detect_kubernetes_secrets_modification_updates                 = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE__", "resource_name")
  audit_log_admin_activity_detect_kubernetes_secrets_modified_sql_columns                 = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_kubernetes_admission_webhook_config_changes_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_kubernetes_cronjob_changes_sql_columns                  = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_kubernetes_cluster_with_public_endpoint_sql_columns     = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_cloud_scheduler_run_job_sql_columns                     = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_container_executed_sql_columns                          = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "audit_log_admin_activity_kubernetes_detections" {
  title       = "Admin Activity Kubernetes Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Kubernetes Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_kubernetes_secrets_modification_updates,
    detection.audit_log_admin_activity_detect_kubernetes_admission_webhook_config_changes,
    detection.audit_log_admin_activity_detect_kubernetes_cronjob_changes,
    detection.audit_log_admin_activity_detect_kubernetes_cluster_with_public_endpoint,
    detection.audit_log_admin_activity_detect_cloud_scheduler_run_job,
  ]

  tags = merge(local.audit_log_admin_activity_kubernetes_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_kubernetes_secrets_modification_updates" {
  title       = "Detect Kubernetes Secrets Modification Updates"
  description = "Detect changes to Kubernetes secrets, ensuring visibility into modifications that could compromise sensitive information or signal unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_kubernetes_secrets_modification_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_kubernetes_admission_webhook_config_changes" {
  title       = "Detect Kubernetes Admission Webhook Config Changes"
  description = "Detect changes to Kubernetes admission webhook configurations, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_kubernetes_admission_webhook_config_changes

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_kubernetes_cronjob_changes" {
  title       = "Detect Kubernetes Cronjob Changes"
  description = "Detect changes to Kubernetes cronjobs, ensuring visibility into modifications that could disrupt scheduled tasks or signal unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_kubernetes_cronjob_changes

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_kubernetes_cluster_with_public_endpoint" {
  title       = "Detect Kubernetes Clusters with Public Endpoints"
  description = "Detect Kubernetes clusters with public endpoints, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_kubernetes_cluster_with_public_endpoint

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0001:T119"
  })
}

detection "audit_log_admin_activity_detect_cloud_scheduler_run_job" {
  title       = "Detect Cloud Scheduler Run Jobs"
  description = "Detect when Cloud Scheduler jobs are run, ensuring visibility into scheduled operations and monitoring for unauthorized or unexpected executions."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_cloud_scheduler_run_job

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0002:T1651"
  })
}

detection "audit_log_admin_activity_detect_container_executed" {
  title       = "Detect Containers Executed"
  description = "Detect the executions of containers, ensuring visibility into runtime activities that might indicate unauthorized actions or potential security risks."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_container_executed

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = "TA0002:T1651"
  })
}

query "audit_log_admin_activity_detect_kubernetes_secrets_modification_updates" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_kubernetes_secrets_modified_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'k8s.io'
      and (method_name ilike 'io.k8s.api.core.v%.secrets.delete' or method_name ilike 'io.k8s.api.core.v%.secrets.update')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_kubernetes_admission_webhook_config_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_kubernetes_admission_webhook_config_changes_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'admissionregistration.k8s.io'
      and (method_name ilike 'admissionregistration.k8s.io.v%.mutatingwebhookconfigurations.create' or method_name ilike 'admissionregistration.k8s.io.v%.mutatingwebhookconfigurations.replace' or method_name ilike 'admissionregistration.k8s.io.v%.validatingwebhookconfigurations.patch')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_kubernetes_cronjob_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_kubernetes_cronjob_changes_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'batch.k8s.io'
      and (method_name ilike 'io.k8s.api.batch.v%.cronjobs.delete' or method_name ilike 'io.k8s.api.batch.v%.cronjobs.update' or method_name ilike 'io.k8s.api.batch.v%.cronjobs.create')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_kubernetes_cluster_with_public_endpoint" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_kubernetes_cluster_with_public_endpoint_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'container.googleapis.com'
      and (method_name ilike 'v%.container.clusters.create' or method_name ilike 'v%.container.clusters.update')
      and (
        cast(json_extract(request, '$.cluster.privateClusterConfig.enablePrivateNodes') as boolean) = false
        or cast(json_extract(request, '$.update.desiredPrivateClusterConfig.enablePrivateEndpoint') as boolean) = false
      )
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_container_executed" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_container_executed_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'kubernetes.io'
      and method_name ilike 'exec'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_cloud_scheduler_run_job" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_cloud_scheduler_run_job_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'cloudscheduler.googleapis.com'
      and method_name ilike 'google.cloud.scheduler.v%.cloudscheduler.runjob'
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}