#!/bin/bash
# ERROR: (gcloud.access-context-manager.policies.create) PERMISSION_DENIED: The caller does not have permission. This command is authenticated as priyanka.chatterjee@turbot.com which is the active a
# Variables
PROJECT_ID="parker-aaa"  # Replace with your project ID
ORG_ID="......"      # Replace with your organization ID
TOTAL_TESTS=0
FAILED_TESTS=0
test_names=()
test_results=()

# Cleanup function
cleanup() {
    echo "Cleaning up resources..."
    gcloud access-context-manager policies list --organization=$ORG_ID --format="value(name)" | while read policy; do
        gcloud access-context-manager policies delete $policy --quiet || true
    done
}

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

# Test 1: Access Policy Creation and Deletion
access_policy_test="
POLICY_ID=\$(gcloud access-context-manager policies create \
    --organization=$ORG_ID \
    --title='test-policy' \
    --format='value(name)') && \
sleep 5 && \
gcloud access-context-manager policies delete \$POLICY_ID --quiet"
run_test "Access Policy Deletion Detection" "$access_policy_test"

# Test 2: Service Perimeter Creation and Deletion
perimeter_test="
POLICY_ID=\$(gcloud access-context-manager policies create \
    --organization=$ORG_ID \
    --title='test-policy-perimeter' \
    --format='value(name)') && \
sleep 5 && \
gcloud access-context-manager perimeters create test-perimeter \
    --policy=\$POLICY_ID \
    --title='test-perimeter' \
    --resources=projects/$PROJECT_ID \
    --restricted-services=storage.googleapis.com && \
sleep 5 && \
gcloud access-context-manager perimeters delete test-perimeter \
    --policy=\$POLICY_ID --quiet && \
gcloud access-context-manager policies delete \$POLICY_ID --quiet"
run_test "Service Perimeter Deletion Detection" "$perimeter_test"

# Test 3: Access Level Creation and Deletion
access_level_test="
POLICY_ID=\$(gcloud access-context-manager policies create \
    --organization=$ORG_ID \
    --title='test-policy-level' \
    --format='value(name)') && \
sleep 5 && \
gcloud access-context-manager levels create test-level \
    --policy=\$POLICY_ID \
    --title='test-level' \
    --basic-level-spec='ipSubnetworks=10.0.0.0/8' && \
sleep 5 && \
gcloud access-context-manager levels delete test-level \
    --policy=\$POLICY_ID --quiet && \
gcloud access-context-manager policies delete \$POLICY_ID --quiet"
run_test "Access Level Deletion Detection" "$access_level_test"

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

# Cleanup before exit
trap cleanup EXIT

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