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
      title = "Logs by Project"
      query = query.activity_dashboard_logs_by_project
      type  = "column"
      width = 6
    }

    chart {
      title = "Logs by Type"
      query = query.activity_dashboard_logs_by_type
      type  = "column"
      width = 6
    }

    chart {
      title = "Top 10 Actors"
      query = query.activity_dashboard_logs_by_actor
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Source IPs (Excluding GCP Internal)"
      query = query.activity_dashboard_logs_by_source_ip
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Services"
      query = query.activity_dashboard_logs_by_service
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Events"
      query = query.activity_dashboard_logs_by_event
      type  = "table"
      width = 6
    }

  }
}

# -----------------------------
# Query Definitions
# -----------------------------

query "activity_dashboard_total_logs" {
  title = "Log Count"

  sql = <<-EOQ
    select
      count(*) as "Total Logs"
    from
      gcp_audit_log;
  EOQ
}

query "activity_dashboard_logs_by_project" {
  title = "Logs by Project"

  sql = <<-EOQ
    select
      split_part(log_name, '/', 2) as "Project",
      count(*) as "Logs"
    from
      gcp_audit_log
    where
      split_part(log_name, '/', 2) is not null
    group by
      split_part(log_name, '/', 2)
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_type" {
  title = "Logs by Type"

  sql = <<-EOQ
    select
      split_part(log_name, '%2F', 2) as "Type",
      count(*) as "Logs"
    from
      gcp_audit_log
    where
      split_part(log_name, '%2F', 2) is not null
    group by
      split_part(log_name, '%2F', 2)
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_service" {
  title = "Logs by Service"

  sql = <<-EOQ
    select
      service_name as "Service",
      count(*) as "Logs"
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

query "activity_dashboard_logs_by_event" {
  title = "Top 10 Events"

  sql = <<-EOQ
    select
      method_name as "Event",
      count(*) as "Logs"
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
  title = "Top 10 Actors"

  sql = <<-EOQ
    select
      authentication_info.principal_email as "Actor",
      count(*) as "Logs"
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
      tp_source_ip as "Source ip",
      count(*) as "Logs"
    from
      gcp_audit_log
    where
      tp_source_ip is not null
      and tp_source_ip != 'gce-internal-ip'
    group by
      tp_source_ip
    order by
      count(*) desc
    limit 10;
  EOQ
}
