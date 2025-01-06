#!/bin/bash

# Variables
PROJECT_ID="parker-aaa"
REGION="us-central1"
APP_NAME="test-app"

# Initialize error tracking
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

echo "Starting App Engine detection tests..."

# 1. Test App Engine Admin API Enable
admin_api_test_command="
gcloud app update \
    --project=$PROJECT_ID \
    --enable-admin-api"
run_test "Enable Admin API" "$admin_api_test_command"

# 2. Test Firewall Rule Creation
create_firewall_rule_command="
gcloud app firewall-rules create test-rule \
    --project=$PROJECT_ID \
    --action=allow \
    --source-range='0.0.0.0/0' \
    --description='Test firewall rule creation'"
run_test "Create Firewall Rule" "$create_firewall_rule_command"

# 3. Test Firewall Rule Modification
modify_firewall_rule_command="
gcloud app firewall-rules update test-rule \
    --project=$PROJECT_ID \
    --action=deny \
    --source-range='10.0.0.0/8' \
    --description='Modified test firewall rule'"
run_test "Modify Firewall Rule" "$modify_firewall_rule_command"

# 4. Test Firewall Rule Deletion
delete_firewall_rule_command="
gcloud app firewall-rules delete test-rule \
    --project=$PROJECT_ID \
    --quiet"
run_test "Delete Firewall Rule" "$delete_firewall_rule_command"

# 5. Test Multiple Rules Creation
multiple_rules_command="
for i in {1..3}; do
    gcloud app firewall-rules create test-rule-\$i \
        --project=$PROJECT_ID \
        --action=allow \
        --source-range=\"192.168.0.\$i/32\" \
        --description=\"Test rule \$i\"
done"
run_test "Create Multiple Rules" "$multiple_rules_command"

# Cleanup
echo "Performing cleanup..."
cleanup_command="
gcloud app firewall-rules list --project=$PROJECT_ID --format='get(priority)' | \
while read -r priority; do
    if [[ \$priority =~ ^test-rule ]]; then
        gcloud app firewall-rules delete \$priority --project=$PROJECT_ID --quiet
    fi
done

# Disable Admin API
gcloud app update --project=$PROJECT_ID --disable-admin-api"
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