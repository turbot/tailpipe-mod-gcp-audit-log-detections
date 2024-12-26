#!/bin/bash

# Variables
PROJECT_ID="parker-aaa"
REGION="us-central1"
REPOSITORY_NAME="test"
TEST_IMAGE="test-image"
KMS_KEY="projects/$PROJECT_ID/locations/$REGION/keyRings/test-keyring/cryptoKeys/test-key"
REPOSITORY_HOST="$REGION-docker.pkg.dev"

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

# Function to check if repository exists
check_repository() {
    gcloud artifacts repositories describe $REPOSITORY_NAME \
        --location=$REGION \
        --project=$PROJECT_ID >/dev/null 2>&1
    return $?
}

# Function to setup Docker authentication
setup_docker_auth() {
    echo "Setting up Docker authentication..."
    # Get GCP credentials token
    ACCESS_TOKEN=$(gcloud auth print-access-token)
    if [ $? -ne 0 ]; then
        echo "Failed to get GCP access token"
        return 1
    fi

    # Configure Docker credential helper for Artifact Registry
    gcloud auth configure-docker $REGION-docker.pkg.dev --quiet
    if [ $? -ne 0 ]; then
        echo "Failed to configure Docker credential helper"
        return 1
    fi

    echo "Docker authentication setup completed"
    return 0
}

echo "Starting Artifact Registry detection tests..."

# Setup Docker authentication
setup_docker_auth
if [ $? -ne 0 ]; then
    echo "Failed to setup Docker authentication. Exiting..."
    exit 1
fi

# 1. Create or update repository test
create_repo_command="
if check_repository; then
    echo 'Repository $REPOSITORY_NAME already exists, skipping creation'
else
    echo 'Creating new repository $REPOSITORY_NAME'
    gcloud artifacts repositories create $REPOSITORY_NAME \\
        --repository-format=docker \\
        --location=$REGION \\
        --project=$PROJECT_ID
fi"
run_test "Create/Update Repository" "$create_repo_command"

# 2. Overwrite latest tag test
overwrite_test_command="
docker pull nginx:latest && \
docker tag nginx:latest $REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY_NAME/$TEST_IMAGE:latest && \
docker push $REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY_NAME/$TEST_IMAGE:latest && \
docker push $REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY_NAME/$TEST_IMAGE:latest"
run_test "Overwrite Latest Tag" "$overwrite_test_command"

# 3. Public accessibility test
public_access_test_command="
gcloud artifacts repositories add-iam-policy-binding $REPOSITORY_NAME \
    --location=$REGION \
    --member='allUsers' \
    --role='roles/artifactregistry.reader'"
run_test "Public Accessibility" "$public_access_test_command"

# 4. No layers test
no_layers_test_command="
cat > Dockerfile.empty << 'EOF'
FROM scratch
EOF
docker build -t $REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY_NAME/empty-image:latest -f Dockerfile.empty . && \
docker push $REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY_NAME/empty-image:latest"
run_test "No Layers Image" "$no_layers_test_command"

# 5. Artifact deletion test
deletion_test_command="
gcloud artifacts docker images delete \
    $REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY_NAME/$TEST_IMAGE:latest \
    --delete-tags \
    --quiet"
run_test "Artifact Deletion" "$deletion_test_command"

# 6. Encrypted container test
encryption_test_command="
gcloud artifacts repositories update $REPOSITORY_NAME \
    --location=$REGION \
    --kms-key=$KMS_KEY && \
docker push $REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY_NAME/$TEST_IMAGE:latest"
run_test "Encrypted Container" "$encryption_test_command"

# Cleanup
echo "Performing cleanup..."
cleanup_command="
gcloud artifacts repositories delete $REPOSITORY_NAME \
    --location=$REGION \
    --quiet"
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
