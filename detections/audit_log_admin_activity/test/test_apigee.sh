#!/bin/bash

# Variables
PROJECT_ID="parker-aaa"
REGION="us-central1"
ORG_NAME="test-org"
ENV_NAME="test-env"
API_PROXY_NAME="test-proxy"
TARGET_SERVICE="test-service"

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

# Function to create API proxy bundle
create_api_proxy_bundle() {
    mkdir -p apiproxy
    cat > apiproxy/proxies/default.xml << EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ProxyEndpoint name="default">
    <HTTPProxyConnection>
        <BasePath>/v1/test</BasePath>
        <VirtualHost>default</VirtualHost>
    </HTTPProxyConnection>
    <RouteRule name="default">
        <TargetEndpoint>default</TargetEndpoint>
    </RouteRule>
</ProxyEndpoint>
EOF

    cat > apiproxy/targets/default.xml << EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<TargetEndpoint name="default">
    <HTTPTargetConnection>
        <URL>http://vulnerable-service.example.com</URL>
    </HTTPTargetConnection>
</TargetEndpoint>
EOF

    cat > apiproxy/test-proxy.xml << EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<APIProxy name="test-proxy">
    <Description>Test proxy for vulnerable service access</Description>
</APIProxy>
EOF

    zip -r apiproxy.zip apiproxy/
}

echo "Starting Apigee detection tests..."

# 1. Create Apigee organization
create_org_command="
gcloud alpha apigee organizations provision \
    --project=$PROJECT_ID \
    --runtime-location=$REGION \
    --analytics-region=$REGION"
run_test "Create Apigee Organization" "$create_org_command"

# 2. Create Apigee environment
create_env_command="
gcloud apigee environments create $ENV_NAME \
    --organization=$PROJECT_ID \
    --description='Test environment'"
run_test "Create Environment" "$create_env_command"

# 3. Create API proxy bundle
create_proxy_bundle_command="
create_api_proxy_bundle"
run_test "Create API Proxy Bundle" "$create_proxy_bundle_command"

# 4. Deploy API proxy
deploy_proxy_command="
gcloud apigee apis create \
    --organization=$PROJECT_ID \
    --name=$API_PROXY_NAME \
    --proxy-zip=apiproxy.zip && \
gcloud apigee apis deploy \
    --organization=$PROJECT_ID \
    --name=$API_PROXY_NAME \
    --environment=$ENV_NAME"
run_test "Deploy API Proxy" "$deploy_proxy_command"

# 5. Simulate access to vulnerable service
simulate_access_command="
# Note: This is a simulation as we can't actually trigger the specific audit log
# Instead, we'll make an API call that should generate related audit logs
curl -X GET \"https://$PROJECT_ID-$ENV_NAME.apigee.net/v1/test\" \
    -H \"Authorization: Bearer \$(gcloud auth print-access-token)\" || true"
run_test "Simulate Vulnerable Service Access" "$simulate_access_command"

# 6. Test API security scan
security_scan_command="
# Note: This is a simulation of a security scan
# In practice, you might use actual security scanning tools
curl -X POST \"https://$PROJECT_ID-$ENV_NAME.apigee.net/v1/test\" \
    -H \"Authorization: Bearer \$(gcloud auth print-access-token)\" \
    -d '{\"test\": \"payload\"}' || true"
run_test "Security Scan Test" "$security_scan_command"

# Cleanup
echo "Performing cleanup..."
cleanup_command="
# Undeploy and delete API proxy
gcloud apigee apis undeploy \
    --organization=$PROJECT_ID \
    --name=$API_PROXY_NAME \
    --environment=$ENV_NAME \
    --quiet

gcloud apigee apis delete \
    --organization=$PROJECT_ID \
    --name=$API_PROXY_NAME \
    --quiet

# Delete environment
gcloud apigee environments delete $ENV_NAME \
    --organization=$PROJECT_ID \
    --quiet

# Clean up local files
rm -rf apiproxy apiproxy.zip"
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