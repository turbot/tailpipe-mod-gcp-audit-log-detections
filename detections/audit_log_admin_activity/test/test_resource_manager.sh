#!/bin/bash

# Variables
PROJECT_ID="parker-aaa"  # Replace with your project ID
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

# 1. Test Project Level IAM Policy Change
project_iam_test="
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member='user:test@example.com' \
    --role='roles/viewer'"
run_test "Project Level IAM Policy Change" "$project_iam_test"

# 2. Test Login Without MFA
# Note: This is simulated as actual login testing requires user interaction
login_mfa_test="
gcloud auth revoke --all && \
gcloud auth login --no-launch-browser"
run_test "Login Without MFA" "$login_mfa_test"

# 3. Test IAM Policy Revocation
iam_revoke_test="
gcloud projects remove-iam-policy-binding $PROJECT_ID \
    --member='user:test@example.com' \
    --role='roles/viewer'"
run_test "IAM Policy Revocation" "$iam_revoke_test"

# 4. Test Script Execution Policy
script_execution_test="
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member='user:test@example.com' \
    --role='roles/cloudfunctions.invoker'"
run_test "Script Execution Policy" "$script_execution_test"

# 5. Test Owner Role Grant
owner_role_test="
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member='user:test@example.com' \
    --role='roles/owner' && \
sleep 2 && \
gcloud projects remove-iam-policy-binding $PROJECT_ID \
    --member='user:test@example.com' \
    --role='roles/owner'"
run_test "Owner Role Grant" "$owner_role_test"

# 6. Test Org Policy Modification
# Note: Requires org admin privileges
org_policy_test="
gcloud org-policies set-policy \
    --project=$PROJECT_ID \
    compute.disableSerialPortAccess \
    --boolean-policy=true"
run_test "Org Policy Modification" "$org_policy_test"

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