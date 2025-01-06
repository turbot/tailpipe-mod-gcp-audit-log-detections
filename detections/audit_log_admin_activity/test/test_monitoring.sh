#!/bin/bash

# Variables
PROJECT_ID="parker-aaa"
METRIC_TYPE="custom.googleapis.com/test_metric"
ALERT_POLICY_NAME="test-alert-policy"
NOTIFICATION_CHANNEL_NAME="test-notification-channel"
FAILED_TESTS=0
TOTAL_TESTS=0
test_names=()
test_results=()

# Function to run test and track result
run_test() {
    local test_name="$1"
    local commands="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    test_names[${#test_names[@]}]="$test_name"
    
    echo "=== Starting test: $test_name ==="
    if eval "$commands"; then
        test_results[${#test_results[@]}]="PASSED"
        echo "✓ Test '$test_name' passed"
    else
        test_results[${#test_results[@]}]="FAILED"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "✗ Test '$test_name' failed"
    fi
    echo "=== End of test: $test_name ==="
    echo
}

# Check GCP authentication
echo "Verifying GCP authentication..."
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" >/dev/null 2>&1; then
    echo "Please authenticate with GCP first using 'gcloud auth login'"
    exit 1
fi

# Enable required APIs
echo "Enabling required APIs..."
api_enable_test="
gcloud services enable \
    monitoring.googleapis.com \
    --project $PROJECT_ID"
run_test "Enable APIs" "$api_enable_test"

# 1. Test Custom Metric Creation
create_metric_test="
# Create a custom metric descriptor
cat << EOF > /tmp/metric_descriptor.json
{
  \"type\": \"$METRIC_TYPE\",
  \"metricKind\": \"GAUGE\",
  \"valueType\": \"DOUBLE\",
  \"description\": \"Test metric for monitoring\",
  \"displayName\": \"Test Metric\"
}
EOF

curl -X POST \
    -H 'Authorization: Bearer '\"$(gcloud auth print-access-token)\"'' \
    -H 'Content-Type: application/json' \
    -d @/tmp/metric_descriptor.json \
    'https://monitoring.googleapis.com/v3/projects/$PROJECT_ID/metricDescriptors'"
run_test "Create Custom Metric" "$create_metric_test"

# 2. Test Writing Metric Data
write_metric_test="
# Write test data point
current_time=\$(date -u +\"%Y-%m-%dT%H:%M:%SZ\")
cat << EOF > /tmp/time_series.json
{
  \"timeSeries\": [{
    \"metric\": {
      \"type\": \"$METRIC_TYPE\"
    },
    \"resource\": {
      \"type\": \"global\",
      \"labels\": {}
    },
    \"points\": [{
      \"interval\": {
        \"endTime\": \"\$current_time\"
      },
      \"value\": {
        \"doubleValue\": 123.45
      }
    }]
  }]
}
EOF

curl -X POST \
    -H 'Authorization: Bearer '\"$(gcloud auth print-access-token)\"'' \
    -H 'Content-Type: application/json' \
    -d @/tmp/time_series.json \
    'https://monitoring.googleapis.com/v3/projects/$PROJECT_ID/timeSeries'"
run_test "Write Metric Data" "$write_metric_test"

# 3. Test Alert Policy Creation
create_alert_test="
cat << EOF > /tmp/alert_policy.json
{
  \"displayName\": \"$ALERT_POLICY_NAME\",
  \"conditions\": [{
    \"displayName\": \"Test Condition\",
    \"conditionThreshold\": {
      \"filter\": \"metric.type = \\\"$METRIC_TYPE\\\"\",
      \"comparison\": \"COMPARISON_GT\",
      \"thresholdValue\": 100,
      \"duration\": \"60s\"
    }
  }],
  \"combiner\": \"OR\"
}
EOF

curl -X POST \
    -H 'Authorization: Bearer '\"$(gcloud auth print-access-token)\"'' \
    -H 'Content-Type: application/json' \
    -d @/tmp/alert_policy.json \
    'https://monitoring.googleapis.com/v3/projects/$PROJECT_ID/alertPolicies'"
run_test "Create Alert Policy" "$create_alert_test"

# 4. Test Notification Channel Creation
create_notification_test="
cat << EOF > /tmp/notification_channel.json
{
  \"displayName\": \"$NOTIFICATION_CHANNEL_NAME\",
  \"type\": \"email\",
  \"labels\": {
    \"email_address\": \"test@example.com\"
  }
}
EOF

curl -X POST \
    -H 'Authorization: Bearer '\"$(gcloud auth print-access-token)\"'' \
    -H 'Content-Type: application/json' \
    -d @/tmp/notification_channel.json \
    'https://monitoring.googleapis.com/v3/projects/$PROJECT_ID/notificationChannels'"
run_test "Create Notification Channel" "$create_notification_test"

# 5. Test Metric Descriptor Deletion
delete_metric_test="
curl -X DELETE \
    -H 'Authorization: Bearer '\"$(gcloud auth print-access-token)\"'' \
    'https://monitoring.googleapis.com/v3/projects/$PROJECT_ID/metricDescriptors/$METRIC_TYPE'"
run_test "Delete Metric Descriptor" "$delete_metric_test"

# 6. Test Audit Log Generation
audit_log_test="
# Wait for logs to be available
sleep 30 && \
gcloud logging read 'resource.type=metric AND \
    resource.labels.project_id=$PROJECT_ID' \
    --project=$PROJECT_ID \
    --limit=10"
run_test "Audit Log Generation" "$audit_log_test"

# Cleanup
echo "Performing cleanup..."
cleanup_command="
# Get and delete alert policies
ALERT_POLICIES=\$(curl -s -H 'Authorization: Bearer '\"$(gcloud auth print-access-token)\"'' \
    'https://monitoring.googleapis.com/v3/projects/$PROJECT_ID/alertPolicies')
echo \"\$ALERT_POLICIES\" | grep -o '\"name\": \"[^\"]*\"' | cut -d'\"' -f4 | while read -r policy; do
    if [ ! -z \"\$policy\" ]; then
        curl -X DELETE -H 'Authorization: Bearer '\"$(gcloud auth print-access-token)\"'' \
            \"https://monitoring.googleapis.com/v3/\$policy\"
    fi
done

# Get and delete notification channels
NOTIFICATION_CHANNELS=\$(curl -s -H 'Authorization: Bearer '\"$(gcloud auth print-access-token)\"'' \
    'https://monitoring.googleapis.com/v3/projects/$PROJECT_ID/notificationChannels')
echo \"\$NOTIFICATION_CHANNELS\" | grep -o '\"name\": \"[^\"]*\"' | cut -d'\"' -f4 | while read -r channel; do
    if [ ! -z \"\$channel\" ]; then
        curl -X DELETE -H 'Authorization: Bearer '\"$(gcloud auth print-access-token)\"'' \
            \"https://monitoring.googleapis.com/v3/\$channel\"
    fi
done

# Remove temporary files
rm -f /tmp/metric_descriptor.json /tmp/time_series.json /tmp/alert_policy.json /tmp/notification_channel.json"
run_test "Cleanup" "$cleanup_command"

# Print test summary
echo "=== Test Summary ==="
echo "Total tests run: $TOTAL_TESTS"
echo "Tests failed: $FAILED_TESTS"
echo
echo "Detailed Results:"
for i in $(seq 0 $((${#test_names[@]} - 1))); do
    test_name=${test_names[$i]}
    result=${test_results[$i]}
    if [ "$result" = "PASSED" ]; then
        echo "✓ $test_name: $result"
    else
        echo "✗ $test_name: $result"
    fi
done

# Print important notes
echo
echo "Important Notes:"
echo "1. Some operations might take time to propagate in the monitoring system"
echo "2. Alert policies might need time to evaluate"
echo "3. Metric data points might not be immediately available in queries"

# Exit with appropriate status
if [ $FAILED_TESTS -gt 0 ]; then
    echo
    echo "✗ Some tests failed. Please check the logs above for details."
    exit 1
else
    echo
    echo "✓ All tests passed successfully!"
    exit 0
fi