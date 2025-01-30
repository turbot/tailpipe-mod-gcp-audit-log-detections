dashboard "activity_dashboard" {
  title = "Audit Log Activity Dashboard"

  tags = {
    type    = "Dashboard"
    service = "GCP/AuditLog"
  }

  container {
    # Single card to show total logs
    card {
      query = query.activity_dashboard_total_logs
      width = 2
    }
  }

  container {

    chart {
      title = "Logs by Severity"
      query = query.activity_dashboard_logs_by_severity
      type  = "column"
      width = 6
    }

    chart {
      title = "Logs by Service"
      query = query.activity_dashboard_logs_by_service
      type  = "column"
      width = 6
    }

    chart {
      title = "Logs by Method"
      query = query.activity_dashboard_logs_by_method
      type  = "column"
      width = 6
    }

    chart {
      title = "Top 10 Principals (Actors)"
      query = query.activity_dashboard_logs_by_actor
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Source IPs"
      query = query.activity_dashboard_logs_by_source_ip
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Resources"
      query = query.activity_dashboard_logs_by_resource
      type  = "table"
      width = 6
    }

  }
}

# -----------------------------
# Query Definitions
# -----------------------------

query "activity_dashboard_total_logs" {
  title = "Total Log Count"

  sql = <<-EOQ
    select
      count(*) as "total logs"
    from
      gcp_audit_log;
  EOQ
}

query "activity_dashboard_logs_by_severity" {
  title = "Logs by Severity"

  sql = <<-EOQ
    select
      severity as "severity",
      count(*) as "logs"
    from
      gcp_audit_log
    where
      severity is not null
    group by
      severity
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_service" {
  title = "Logs by Service"

  sql = <<-EOQ
    select
      service_name as "service",
      count(*) as "logs"
    from
      gcp_audit_log
    where
      service_name is not null
    group by
      service_name
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_method" {
  title = "Logs by Method"

  sql = <<-EOQ
    select
      method_name as "method",
      count(*) as "logs"
    from
      gcp_audit_log
    where
      method_name is not null
    group by
      method_name
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_actor" {
  title = "Top 10 Principals (Actors)"

  sql = <<-EOQ
    select
      authentication_info.principal_email as "principal email",
      count(*) as "logs"
    from
      gcp_audit_log
    where
      authentication_info.principal_email is not null
    group by
      authentication_info.principal_email
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_source_ip" {
  title = "Top 10 Source IPs"

  sql = <<-EOQ
    select
      tp_source_ip as "source ip",
      count(*) as "logs"
    from
      gcp_audit_log
    where
      tp_source_ip is not null
    group by
      tp_source_ip
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_resource" {
  title = "Top 10 Resources"

  sql = <<-EOQ
    select
      resource_name as "resource name",
      count(*) as "logs"
    from
      gcp_audit_log
    where
      resource_name is not null
    group by
      resource_name
    order by
      count(*) desc
    limit 10;
  EOQ
}