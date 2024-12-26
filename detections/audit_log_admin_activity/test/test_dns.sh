#!/bin/bash

# Variables
PROJECT_ID="parker-aaa"
DNS_ZONE_NAME="test-zone"
DNS_DOMAIN="test-domain.com."
RECORD_SET_NAME="www.test-domain.com."

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

# Function to create transaction file for DNS changes
create_transaction_file() {
    cat << EOF > dns_changes.yaml
---
additions:
- kind: dns#resourceRecordSet
  name: $RECORD_SET_NAME
  type: A
  ttl: 300
  rrdatas:
  - "192.0.2.1"
deletions: []
EOF
}

# 1. Enable Cloud DNS API
enable_dns_test="
gcloud services enable dns.googleapis.com --project=$PROJECT_ID"
run_test "Enable Cloud DNS API" "$enable_dns_test"

# 2. Create DNS Zone
create_zone_test="
gcloud dns managed-zones create $DNS_ZONE_NAME \
    --dns-name=$DNS_DOMAIN \
    --description='Test DNS zone' \
    --project=$PROJECT_ID"
run_test "Create DNS Zone" "$create_zone_test"

# 3. Modify DNS Zone
modify_zone_test="
gcloud dns managed-zones update $DNS_ZONE_NAME \
    --description='Modified test DNS zone' \
    --project=$PROJECT_ID"
run_test "Modify DNS Zone" "$modify_zone_test"

# 4. Create DNS Record
create_record_test="
create_transaction_file && \
gcloud dns record-sets import dns_changes.yaml \
    --zone=$DNS_ZONE_NAME \
    --project=$PROJECT_ID" --log-http
run_test "Create DNS Record" "$create_record_test"

# 5. Modify DNS Record
modify_record_test="
gcloud dns record-sets update $RECORD_SET_NAME \
    --type=A \
    --ttl=600 \
    --rrdatas=192.0.2.2 \
    --zone=$DNS_ZONE_NAME \
    --project=$PROJECT_ID"
run_test "Modify DNS Record" "$modify_record_test"

# 6. Delete DNS Record
delete_record_test="
gcloud dns record-sets delete $RECORD_SET_NAME \
    --type=A \
    --zone=$DNS_ZONE_NAME \
    --project=$PROJECT_ID"
run_test "Delete DNS Record" "$delete_record_test"

# 7. Delete DNS Zone
delete_zone_test="
gcloud dns managed-zones delete $DNS_ZONE_NAME \
    --project=$PROJECT_ID \
    --quiet"
run_test "Delete DNS Zone" "$delete_zone_test"

# 8. Cleanup
cleanup_test="
rm -f dns_changes.yaml"
run_test "Cleanup" "$cleanup_test"

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