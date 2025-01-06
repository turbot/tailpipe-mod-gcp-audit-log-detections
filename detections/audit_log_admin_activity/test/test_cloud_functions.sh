#!/bin/bash

# Variables
PROJECT_ID="parker-aaa"
REGION="us-central1"
FUNCTION_NAME="test-function"
BUCKET_NAME="test-function-bucket-${PROJECT_ID}"
TOPIC_NAME="test-function-topic"
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

# Function to create a sample function
create_sample_function() {
    # Create a temporary directory for function code
    mkdir -p /tmp/function
    cat > /tmp/function/index.js << 'EOF'
exports.helloWorld = (req, res) => {
  res.send('Hello, World!');
};
EOF

    cat > /tmp/function/package.json << 'EOF'
{
  "name": "sample-function",
  "version": "1.0.0",
  "main": "index.js"
}
EOF
}

# Check GCP authentication
echo "Verifying GCP authentication..."
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" >/dev/null 2>&1; then
    echo "Please authenticate with GCP first using 'gcloud auth login'"
    exit 1
fi

# Enable required APIs
echo "Enabling required APIs..."
gcloud services enable \
    cloudfunctions.googleapis.com \
    cloudbuild.googleapis.com \
    storage.googleapis.com \
    pubsub.googleapis.com \
    --quiet

# Create sample function
create_sample_function

# 1. Test Function Creation
function_creation_test="
# Create storage bucket for function code
gsutil mb -p $PROJECT_ID -l $REGION gs://$BUCKET_NAME && \

# Create a temporary directory and zip the function files
cd /tmp/function && \
zip -r function.zip * && \

# Upload the zip file to the bucket
gsutil cp function.zip gs://$BUCKET_NAME/ && \

# Deploy function
gcloud functions deploy $FUNCTION_NAME \
    --runtime nodejs16 \
    --trigger-http \
    --source gs://$BUCKET_NAME/function.zip \
    --entry-point helloWorld \
    --region $REGION \
    --project $PROJECT_ID \
    --quiet"
run_test "Function Creation" "$function_creation_test"

# 2. Test Public Access Configuration
public_access_test="
# Make function publicly accessible
gcloud functions add-iam-policy-binding $FUNCTION_NAME \
    --region=$REGION \
    --member='allUsers' \
    --role='roles/cloudfunctions.invoker' && \

# Verify IAM policy
gcloud functions get-iam-policy $FUNCTION_NAME \
    --region=$REGION \
    --format='json' | grep 'allUsers'"
run_test "Public Access Configuration" "$public_access_test"

# 3. Test Function Deletion
function_deletion_test="
# Delete the function
gcloud functions delete $FUNCTION_NAME \
    --region=$REGION \
    --quiet"
run_test "Function Deletion" "$function_deletion_test"

# 4. Test Audit Log Generation
audit_log_test="
# Wait for logs to be available
sleep 30 && \
gcloud logging read 'resource.type=cloud_function AND \
    resource.labels.function_name=$FUNCTION_NAME' \
    --project=$PROJECT_ID \
    --limit=10"
run_test "Audit Log Generation" "$audit_log_test"

# Cleanup
echo "Performing cleanup..."
cleanup_command="
# Delete storage bucket
gsutil -m rm -r gs://$BUCKET_NAME || true

# Remove temporary files
rm -rf /tmp/function"
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
