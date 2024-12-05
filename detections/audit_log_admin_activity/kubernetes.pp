locals {
  audit_log_admin_activity_kubernetes_detection_common_tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    service = "Kubernetes"
  })

  audit_log_admin_activity_detect_kubernetes_secrets_modification_updates                 = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE__", "resource_name")
  audit_log_admin_activity_detect_kubernetes_secrets_modified_sql_columns                 = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_kubernetes_admission_webhook_config_changes_sql_columns = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_kubernetes_cronjob_changes_sql_columns                  = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
  audit_log_admin_activity_detect_kubernetes_role_binding_changes_sql_columns             = replace(local.audit_log_admin_activity_detection_sql_columns, "__RESOURCE_SQL__", "resource_name")
}

detection_benchmark "audit_log_admin_activity_kubernetes_detections" {
  title       = "Admin Activity Kubernetes Logs Detections"
  description = "This detection benchmark contains recommendations when scanning GCP Admin Activity Kubernetes Logs."
  type        = "detection"
  children = [
    detection.audit_log_admin_activity_detect_kubernetes_secrets_modification_updates,
    detection.audit_log_admin_activity_detect_kubernetes_admission_webhook_config_changes,
    detection.audit_log_admin_activity_detect_kubernetes_cronjob_changes,
    detection.audit_log_admin_activity_detect_kubernetes_role_binding_changes,
  ]

  tags = merge(local.audit_log_admin_activity_kubernetes_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "audit_log_admin_activity_detect_kubernetes_secrets_modification_updates" {
  title       = "Detect Kubernetes Secrets Modification Updates"
  description = "Detect changes to Kubernetes secrets that might compromise sensitive information or indicate unauthorized access attempts"
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_kubernetes_secrets_modification_updates

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_kubernetes_admission_webhook_config_changes" {
  title       = "Detect Kubernetes Admission Webhook Config Changes"
  description = "Detect changes to Kubernetes admission webhook configurations that might expose resources to threats or indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_kubernetes_admission_webhook_config_changes

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_kubernetes_cronjob_changes" {
  title       = "Detect Kubernetes Cronjob Changes"
  description = "Detect changes to Kubernetes cronjobs that might disrupt scheduled tasks or indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_kubernetes_cronjob_changes

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "audit_log_admin_activity_detect_kubernetes_role_binding_changes" {
  title       = "Detect Kubernetes Role Binding Changes"
  description = "Detect changes to Kubernetes role bindings that might expose resources to threats or indicate unauthorized access attempts."
  severity    = "medium"
  query       = query.audit_log_admin_activity_detect_kubernetes_role_binding_changes

  tags = merge(local.audit_log_admin_activity_detection_common_tags, {
    mitre_attack_ids = ""
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
      and method_name in ('io.k8s.api.core.v1.secrets.delete', 'io.k8s.api.core.v1.secrets.update')
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
      and method_name in ('admissionregistration.k8s.io.v1.mutatingwebhookconfigurations.create', 'admissionregistration.k8s.io.v1.mutatingwebhookconfigurations.replace', 'admissionregistration.k8s.io.v1.validatingwebhookconfigurations.patch')
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
      and method_name in ('io.k8s.api.batch.v1.cronjobs.delete', 'io.k8s.api.batch.v1.cronjobs.update', 'io.k8s.api.batch.v1.cronjobs.create')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "audit_log_admin_activity_detect_kubernetes_role_binding_changes" {
  sql = <<-EOQ
    select
      ${local.audit_log_admin_activity_detect_kubernetes_role_binding_changes_sql_columns}
    from
      gcp_audit_log_admin_activity
    where
      service_name = 'rbac.authorization.k8s.io'
      and method_name in ('io.k8s.authorization.rbac.v1.rolebindings.delete', 'io.k8s.authorization.rbac.v1.clusterrolebindings.update', 'io.k8s.authorization.rbac.v1.rolebindings.patch', 'io.k8s.authorization.rbac.v1.clusterrolebindings.create')
      ${local.audit_log_admin_activity_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
