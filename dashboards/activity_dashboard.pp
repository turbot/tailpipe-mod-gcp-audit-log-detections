dashboard "activity_dashboard" {

  title         = "Audit Log Activity Dashboard"
  documentation = file("./dashboards/docs/activity_dashboard.md")

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
  title       = "Log Count"
  description = "Count the total log entries."

  sql = <<-EOQ
    select
      count(*) as "Total Logs"
    from
      gcp_audit_log;
  EOQ

  tags = {
    folder = "Project"
  }
}

query "activity_dashboard_logs_by_project" {
  title       = "Logs by Project"
  description = "Count the total log entries grouped by project."

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

  tags = {
    folder = "Project"
  }
}

query "activity_dashboard_logs_by_type" {
  title       = "Logs by Type"
  description = "Count the total log entries grouped by type."

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

  tags = {
    folder = "Project"
  }
}

query "activity_dashboard_logs_by_service" {
  title       = "Logs by Service"
  description = "Count the total log entries grouped by service."

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

  tags = {
    folder = "Project"
  }
}

query "activity_dashboard_logs_by_event" {
  title       = "Top 10 Events"
  description = "List the 10 most frequently called events."

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

  tags = {
    folder = "Project"
  }
}

query "activity_dashboard_logs_by_actor" {
  title       = "Top 10 Actors"
  description = "List the 10 most active actors."

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

  tags = {
    folder = "Project"
  }
}

query "activity_dashboard_logs_by_source_ip" {
  title       = "Top 10 Source IPs"
  description = "List the 10 most active source IPs."

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

  tags = {
    folder = "Project"
  }
}
