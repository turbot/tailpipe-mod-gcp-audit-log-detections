#!/bin/bash

# Variables
PROJECT_ID=$(gcloud config get-value project)
REGION="us-central1"
SERVICE_ACCOUNT_NAME="test-sa"
SERVICE_ACCOUNT_EMAIL="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
WORKFORCE_POOL_ID="test-workforce-pool"
PROVIDER_ID="test-provider"
CUSTOM_ROLE_NAME="testCustomRole"
CURRENT_USER=$(gcloud config get-value account)
# Get organization ID
ORG_ID=$(gcloud projects get-ancestors $PROJECT_ID --format="get(id)" | tail -1)
if [ -z "$ORG_ID" ]; then
    echo "Error: Could not determine organization ID. Please ensure you have access to the organization."
    echo "You can manually set it by modifying the ORG_ID variable in the script."
    exit 1
fi

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
    test_names+=("$test_name")
    
    echo "=== Starting test: $test_name ==="
    if eval "$commands"; then
        test_results+=("PASSED")
        echo "✓ Test '$test_name' passed"
    else
        test_results+=("FAILED")
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "✗ Test '$test_name' failed"
    fi
    echo "=== End of test: $test_name ==="
    echo
}

# 1. Service Account Creation Test
create_sa_command="
gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME \
    --display-name='Test Service Account' \
    --description='Service account for testing IAM detections'"
run_test "Service Account Creation" "$create_sa_command"

# 2. Service Account Key Creation Test
create_key_command="
gcloud iam service-accounts keys create key.json \
    --iam-account=$SERVICE_ACCOUNT_EMAIL"
run_test "Service Account Key Creation" "$create_key_command"

# 3. Grant Token Creator Role Test
grant_token_creator_command="
sleep 10 && \
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member=serviceAccount:$SERVICE_ACCOUNT_EMAIL \
    --role=roles/iam.serviceAccountTokenCreator"
run_test "Grant Token Creator Role" "$grant_token_creator_command"

grant_user_token_creator_command="
gcloud iam service-accounts add-iam-policy-binding $SERVICE_ACCOUNT_EMAIL \
    --member=user:$CURRENT_USER \
    --role=roles/iam.serviceAccountTokenCreator"
run_test "Grant Token Creator Role to User" "$grant_user_token_creator_command"

# 4. Create Custom High-Privilege Role Test
create_custom_role_command="
gcloud iam roles create $CUSTOM_ROLE_NAME \
    --project=$PROJECT_ID \
    --permissions=resourcemanager.projects.setIamPolicy"
run_test "Create Custom High-Privilege Role" "$create_custom_role_command"

# 5. Grant Public Access Test
grant_public_access_command="
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member=allAuthenticatedUsers \
    --role=roles/viewer"
run_test "Grant Public Access" "$grant_public_access_command"

# 6. Create Workforce Pool Test
create_workforce_pool_command="
gcloud iam workforce-pools create $WORKFORCE_POOL_ID \
    --location=$REGION \
    --organization=$ORG_ID \
    --display-name='Test Workforce Pool'"
run_test "Create Workforce Pool" "$create_workforce_pool_command"

# 7. Create Workforce Pool Provider Test (only if workforce pool creation succeeded)
if [[ " ${test_results[@]} " =~ "FAILED" ]]; then
    echo "Skipping workforce pool provider creation as workforce pool creation failed"
    test_names+=("Create Workforce Pool Provider")
    test_results+=("SKIPPED")
else
    create_provider_command="
    gcloud iam workforce-pools providers create-oidc $PROVIDER_ID \
        --workforce-pool=$WORKFORCE_POOL_ID \
        --location=$REGION \
        --organization=$ORG_ID \
        --issuer-uri='https://accounts.google.com' \
        --client-id='test-client-id'"
    run_test "Create Workforce Pool Provider" "$create_provider_command"
fi

# 8. Generate Service Account Token Test
generate_token_command="
gcloud auth print-access-token --impersonate-service-account=$SERVICE_ACCOUNT_EMAIL"
run_test "Generate Service Account Token" "$generate_token_command"

# 9. Grant API Gateway Admin Role Test
grant_apigateway_admin_command="
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member=serviceAccount:$SERVICE_ACCOUNT_EMAIL \
    --role=roles/apigateway.admin"
run_test "Grant API Gateway Admin Role" "$grant_apigateway_admin_command"

# 10. Remove Logging Admin Role Test
remove_logging_admin_command="
gcloud projects remove-iam-policy-binding $PROJECT_ID \
    --member=serviceAccount:$SERVICE_ACCOUNT_EMAIL \
    --role=roles/logging.admin"
run_test "Remove Logging Admin Role" "$remove_logging_admin_command"

# 11. Disable Service Account Test
disable_sa_command="
gcloud iam service-accounts disable $SERVICE_ACCOUNT_EMAIL"
run_test "Disable Service Account" "$disable_sa_command"

# 12. Delete Service Account Test
delete_sa_command="
gcloud iam service-accounts delete $SERVICE_ACCOUNT_EMAIL --quiet"
run_test "Delete Service Account" "$delete_sa_command"

# Cleanup remaining resources
echo "=== Performing cleanup ==="

# Remove Token Creator role from current user
gcloud iam service-accounts remove-iam-policy-binding $SERVICE_ACCOUNT_EMAIL \
    --member=user:$CURRENT_USER \
    --role=roles/iam.serviceAccountTokenCreator --quiet 2>/dev/null || true

# Remove public access
gcloud projects remove-iam-policy-binding $PROJECT_ID \
    --member=allAuthenticatedUsers \
    --role=roles/viewer --quiet

# Delete custom role
gcloud iam roles delete $CUSTOM_ROLE_NAME \
    --project=$PROJECT_ID --quiet

# Cleanup workforce pool resources if they were created
if [[ -n "$ORG_ID" ]]; then
    # Delete workforce pool provider if it exists
    gcloud iam workforce-pools providers delete $PROVIDER_ID \
        --workforce-pool=$WORKFORCE_POOL_ID \
        --location=$REGION \
        --organization=$ORG_ID --quiet 2>/dev/null || true
    
    # Delete workforce pool if it exists
    gcloud iam workforce-pools delete $WORKFORCE_POOL_ID \
        --location=$REGION \
        --organization=$ORG_ID --quiet 2>/dev/null || true
fi

# Delete service account key
rm -f key.json

# Print test summary
echo "=== Test Summary ==="
echo "Total tests run: $TOTAL_TESTS"
echo "Tests failed: $FAILED_TESTS"
echo
echo "Detailed Results:"
for i in "${!test_names[@]}"; do
    if [ "${test_results[$i]}" = "PASSED" ]; then
        echo "✓ ${test_names[$i]}: ${test_results[$i]}"
    elif [ "${test_results[$i]}" = "SKIPPED" ]; then
        echo "- ${test_names[$i]}: ${test_results[$i]}"
    else
        echo "✗ ${test_names[$i]}: ${test_results[$i]}"
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