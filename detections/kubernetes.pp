locals {
  kubernetes_common_tags = merge(local.gcp_audit_log_detections_common_tags, {
    service = "GCP/Kubernetes"
  })

  detect_kubernetes_secrets_deletions_sql_columns                      = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_kubernetes_secrets_modified_sql_columns                       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_kubernetes_admission_webhook_config_creations_sql_columns     = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_kubernetes_admission_webhook_config_replaced_sql_columns      = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_kubernetes_admission_webhook_config_modifications_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_kubernetes_cronjob_deletions_sql_columns                      = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_kubernetes_cluster_with_public_endpoint_sql_columns           = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_cloud_scheduler_run_job_sql_columns                           = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_container_executed_sql_columns                                = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  detect_kubernetes_cronjob_modifications_sql_columns                  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

benchmark "kubernetes_detections" {
  title       = "Kubernetes Detections"
  description = "This benchmark contains recommendations when scanning Admin Activity audit logs for Kubernetes events."
  type        = "detection"
  children = [
    detection.detect_kubernetes_secrets_deletions,
    detection.detect_kubernetes_cronjob_deletions,
    detection.detect_kubernetes_cronjob_modifications,
    detection.detect_kubernetes_admission_webhook_config_creations,
    detection.detect_kubernetes_admission_webhook_config_replaced,
    detection.detect_kubernetes_admission_webhook_config_modifications,
    detection.detect_kubernetes_cluster_with_public_endpoint,
    detection.detect_cloud_scheduler_run_job,
  ]

  tags = merge(local.kubernetes_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_kubernetes_secrets_deletions" {
  title           = "Detect Kubernetes Secrets Deletions"
  description     = "Detect deletions of Kubernetes secrets, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_kubernetes_secrets_deletions
  display_columns = local.detection_display_columns

  tags = merge(local.kubernetes_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "detect_kubernetes_cronjob_deletions" {
  title           = "Detect Kubernetes Cronjob Deletions"
  description     = "Detect deletions of Kubernetes cronjobs, ensuring visibility into modifications that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_kubernetes_cronjob_deletions
  display_columns = local.detection_display_columns

  tags = merge(local.kubernetes_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "detect_kubernetes_cronjob_modifications" {
  title           = "Detect Kubernetes Cronjob Modifications"
  description     = "Detect modifications to Kubernetes cronjobs, ensuring visibility into changes that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_kubernetes_cronjob_modifications
  display_columns = local.detection_display_columns

  tags = merge(local.kubernetes_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "detect_kubernetes_admission_webhook_config_creations" {
  title           = "Detect Kubernetes Admission Webhook Config Creations"
  description     = "Detect creations of Kubernetes admission webhook configurations, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_kubernetes_admission_webhook_config_creations
  display_columns = local.detection_display_columns

  tags = merge(local.kubernetes_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "detect_kubernetes_admission_webhook_config_replaced" {
  title           = "Detect Kubernetes Admission Webhook Config Replaced"
  description     = "Detect replacements of Kubernetes admission webhook configurations, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_kubernetes_admission_webhook_config_replaced
  display_columns = local.detection_display_columns

  tags = merge(local.kubernetes_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "detect_kubernetes_admission_webhook_config_modifications" {
  title           = "Detect Kubernetes Admission Webhook Config Modifications"
  description     = "Detect modifications to Kubernetes admission webhook configurations, ensuring visibility into changes that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_kubernetes_admission_webhook_config_modifications
  display_columns = local.detection_display_columns

  tags = merge(local.kubernetes_common_tags, {
    mitre_attack_ids = "TA0004:T1078"
  })
}

detection "detect_kubernetes_cluster_with_public_endpoint" {
  title           = "Detect Kubernetes Clusters with Public Endpoints"
  description     = "Detect Kubernetes clusters with public endpoints, ensuring visibility into configurations that might expose resources to threats or signal unauthorized access attempts."
  severity        = "medium"
  query           = query.detect_kubernetes_cluster_with_public_endpoint
  display_columns = local.detection_display_columns

  tags = merge(local.kubernetes_common_tags, {
    mitre_attack_ids = "TA0001:T119"
  })
}

detection "detect_cloud_scheduler_run_job" {
  title           = "Detect Cloud Scheduler Run Jobs"
  description     = "Detect when Cloud Scheduler jobs are run, ensuring visibility into scheduled operations and monitoring for unauthorized or unexpected executions."
  severity        = "medium"
  query           = query.detect_cloud_scheduler_run_job
  display_columns = local.detection_display_columns

  tags = merge(local.kubernetes_common_tags, {
    mitre_attack_ids = "TA0002:T1651"
  })
}

detection "detect_container_executed" {
  title           = "Detect Containers Executed"
  description     = "Detect the executions of containers, ensuring visibility into runtime activities that might indicate unauthorized actions or potential security risks."
  severity        = "medium"
  query           = query.detect_container_executed
  display_columns = local.detection_display_columns

  tags = merge(local.kubernetes_common_tags, {
    mitre_attack_ids = "TA0002:T1651"
  })
}

query "detect_kubernetes_secrets_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_kubernetes_secrets_deletions_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'k8s.io'
      and method_name ilike 'io.k8s.api.core.v%.secrets.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_kubernetes_secrets_update" {
  sql = <<-EOQ
    select
      ${local.detect_kubernetes_secrets_modified_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'k8s.io'
      and method_name ilike 'io.k8s.api.core.v%.secrets.update'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_kubernetes_admission_webhook_config_creations" {
  sql = <<-EOQ
    select
      ${local.detect_kubernetes_admission_webhook_config_creations_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'admissionregistration.k8s.io'
      and method_name ilike 'admissionregistration.k8s.io.v%.mutatingwebhookconfigurations.create'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_kubernetes_admission_webhook_config_replaced" {
  sql = <<-EOQ
    select
      ${local.detect_kubernetes_admission_webhook_config_replaced_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'admissionregistration.k8s.io'
      and method_name ilike 'admissionregistration.k8s.io.v%.mutatingwebhookconfigurations.replace'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_kubernetes_admission_webhook_config_modifications" {
  sql = <<-EOQ
    select
      ${local.detect_kubernetes_admission_webhook_config_modifications_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'admissionregistration.k8s.io'
      and method_name ilike 'admissionregistration.k8s.io.v%.validatingwebhookconfigurations.patch'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_kubernetes_cronjob_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_kubernetes_cronjob_deletions_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'batch.k8s.io'
      and method_name ilike 'io.k8s.api.batch.v%.cronjobs.delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_kubernetes_cronjob_modifications" {
  sql = <<-EOQ
    select
      ${local.detect_kubernetes_cronjob_modifications_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'batch.k8s.io'
      and method_name ilike 'io.k8s.api.batch.v%.cronjobs.update'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
// testing needed
query "detect_kubernetes_cluster_with_public_endpoint" {
  sql = <<-EOQ
    select
      ${local.detect_kubernetes_cluster_with_public_endpoint_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'container.googleapis.com'
      and (method_name ilike 'v%.container.clusters.create' or method_name ilike 'v%.container.clusters.update')
      and (
        cast(json_extract(request, '$.cluster.privateClusterConfig.enablePrivateNodes') as boolean) = false
        or cast(json_extract(request, '$.update.desiredPrivateClusterConfig.enablePrivateEndpoint') as boolean) = false
      )
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_container_executed" {
  sql = <<-EOQ
    select
      ${local.detect_container_executed_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'kubernetes.io'
      and method_name ilike 'exec'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_cloud_scheduler_run_job" {
  sql = <<-EOQ
    select
      ${local.detect_cloud_scheduler_run_job_sql_columns}
    from
      gcp_audit_log
    where
      service_name = 'cloudscheduler.googleapis.com'
      and method_name ilike 'google.cloud.scheduler.v%.cloudscheduler.runjob'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}