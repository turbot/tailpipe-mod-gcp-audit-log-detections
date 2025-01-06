#!/bin/bash

# Variables
PROJECT_ID="parker-aaa"
REGION="us-central1"
API_ID="test-api"
API_CONFIG_ID="test-config"
GATEWAY_ID="test-gateway"
SERVICE_ACCOUNT="test-sa"

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

# Function to create OpenAPI spec file with backend command execution
create_openapi_spec() {
    cat > openapi.yaml << EOF
swagger: '2.0'
info:
  title: Test API
  description: API Gateway test configuration
  version: 1.0.0
schemes:
  - https
produces:
  - application/json
paths:
  /test:
    get:
      summary: Test endpoint
      operationId: test
      x-google-backend:
        address: https://example.com/execute-command
        path_translation: CONSTANT_ADDRESS
      responses:
        '200':
          description: Successful response
          schema:
            type: object
EOF
}

echo "Starting API Gateway detection tests..."

# 1. Create service account
create_sa_command="
gcloud iam service-accounts create $SERVICE_ACCOUNT \
    --project=$PROJECT_ID \
    --display-name='Test API Gateway SA'"
run_test "Create Service Account" "$create_sa_command"

# 2. Create API
create_api_command="
gcloud api-gateway apis create $API_ID \
    --project=$PROJECT_ID \
    --display-name='Test API'"
run_test "Create API" "$create_api_command"

# 3. Create OpenAPI spec with backend command execution
create_spec_command="
create_openapi_spec"
run_test "Create OpenAPI Spec" "$create_spec_command"

# 4. Create API Config with backend command execution
create_config_command="
gcloud api-gateway api-configs create $API_CONFIG_ID \
    --api=$API_ID \
    --openapi-spec=openapi.yaml \
    --project=$PROJECT_ID \
    --backend-auth-service-account=$SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com"
run_test "Create API Config" "$create_config_command"

# 5. Create Gateway
create_gateway_command="
gcloud api-gateway gateways create $GATEWAY_ID \
    --api=$API_ID \
    --api-config=$API_CONFIG_ID \
    --location=$REGION \
    --project=$PROJECT_ID"
run_test "Create Gateway" "$create_gateway_command"

# 6. Update API Config with different backend command
update_config_command="
sed -i 's|example.com/execute-command|example.com/execute-command-updated|g' openapi.yaml && \
gcloud api-gateway api-configs create ${API_CONFIG_ID}-v2 \
    --api=$API_ID \
    --openapi-spec=openapi.yaml \
    --project=$PROJECT_ID \
    --backend-auth-service-account=$SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com"
run_test "Update API Config" "$update_config_command"

# Cleanup
echo "Performing cleanup..."
cleanup_command="
# Delete Gateway
gcloud api-gateway gateways delete $GATEWAY_ID \
    --location=$REGION \
    --project=$PROJECT_ID \
    --quiet

# Delete API Configs
gcloud api-gateway api-configs list \
    --api=$API_ID \
    --project=$PROJECT_ID \
    --format='value(name)' | \
while read -r config; do
    gcloud api-gateway api-configs delete \$config \
        --api=$API_ID \
        --project=$PROJECT_ID \
        --quiet
done

# Delete API
gcloud api-gateway apis delete $API_ID \
    --project=$PROJECT_ID \
    --quiet

# Delete Service Account
gcloud iam service-accounts delete $SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com \
    --project=$PROJECT_ID \
    --quiet

# Remove OpenAPI spec file
rm -f openapi.yaml"
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