#!/bin/bash

# Variables
PROJECT_ID="parker-aaa"
LOCATION="global"
SINK_NAME="test-sink"
LOG_BUCKET="test-log-bucket"
DESTINATION_BUCKET="test-destination-bucket"

# Initialize error tracking
TOTAL_TESTS=0
FAILED_TESTS=0
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

# 1. Enable Required APIs
enable_apis_test="
gcloud services enable logging.googleapis.com --project=$PROJECT_ID && \
gcloud services enable storage.googleapis.com --project=$PROJECT_ID"
run_test "Enable Required APIs" "$enable_apis_test"

# 2. Create Storage Bucket for Log Sink
create_storage_bucket_test="
gsutil mb -p $PROJECT_ID -l $LOCATION gs://$DESTINATION_BUCKET"
run_test "Create Storage Bucket" "$create_storage_bucket_test"

# 3. Create Log Sink
create_sink_test="
gcloud logging sinks create $SINK_NAME \
    storage.googleapis.com/projects/$PROJECT_ID/buckets/$DESTINATION_BUCKET \
    --log-filter='resource.type=gce_instance' \
    --project=$PROJECT_ID"
run_test "Create Log Sink" "$create_sink_test"

# 4. Create Logging Bucket
create_log_bucket_test="
gcloud logging buckets create $LOG_BUCKET \
    --project=$PROJECT_ID \
    --location=$LOCATION"
run_test "Create Logging Bucket" "$create_log_bucket_test"

# 5. Delete Log Sink
delete_sink_test="
gcloud logging sinks delete $SINK_NAME \
    --project=$PROJECT_ID \
    --quiet"
run_test "Delete Log Sink" "$delete_sink_test"

# 7. Delete Logging Bucket
delete_log_bucket_test="
gcloud logging buckets delete $LOG_BUCKET \
    --project=$PROJECT_ID \
    --location=$LOCATION \
    --quiet"
run_test "Delete Logging Bucket" "$delete_log_bucket_test"

# 8. Cleanup Resources
cleanup_test="
gsutil rm -r gs://$DESTINATION_BUCKET"
run_test "Cleanup Resources" "$cleanup_test"

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

# Exit with failure if any tests failed
if [ $FAILED_TESTS -gt 0 ]; then
    echo
    echo "✗ Some tests failed. Please check the logs above for details."
    exit 1
else
    echo
    echo "✓ All tests passed successfully!"
    exit 0
fi