#!/bin/bash

# Variables
PROJECT_ID="your-project-id"
CLUSTER_NAME="test-cluster"
REGION="us-central1"
ZONE="${REGION}-a"
NAMESPACE="test-namespace"
SECRET_NAME="test-secret"
CRONJOB_NAME="test-cronjob"
WEBHOOK_NAME="test-webhook"
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

# Check GCP authentication
echo "Verifying GCP authentication..."
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" >/dev/null 2>&1; then
    echo "Please authenticate with GCP first using 'gcloud auth login'"
    exit 1
fi

# Enable required APIs
echo "Enabling required APIs..."
api_enable_test="
gcloud services enable \
    container.googleapis.com \
    cloudscheduler.googleapis.com \
    --project $PROJECT_ID"
run_test "Enable APIs" "$api_enable_test"

# 1. Create GKE Cluster with Public Endpoint
create_cluster_test="
gcloud container clusters create $CLUSTER_NAME \
    --zone $ZONE \
    --no-enable-private-nodes \
    --project $PROJECT_ID \
    --num-nodes 1 \
    --machine-type e2-standard-2"
run_test "Create Cluster with Public Endpoint" "$create_cluster_test"

# 2. Get cluster credentials
get_credentials_test="
gcloud container clusters get-credentials $CLUSTER_NAME \
    --zone $ZONE \
    --project $PROJECT_ID"
run_test "Get Cluster Credentials" "$get_credentials_test"

# 3. Create namespace
create_namespace_test="
kubectl create namespace $NAMESPACE"
run_test "Create Namespace" "$create_namespace_test"

# 4. Create and Delete Secret
secret_test="
# Create secret
kubectl create secret generic $SECRET_NAME \
    --from-literal=username=admin \
    --from-literal=password=secret123 \
    -n $NAMESPACE && \
# Delete secret
kubectl delete secret $SECRET_NAME -n $NAMESPACE"
run_test "Create and Delete Secret" "$secret_test"

# 5. Create and Modify CronJob
cronjob_test="
# Create cronjob
cat << EOF | kubectl apply -f -
apiVersion: batch/v1
kind: CronJob
metadata:
  name: $CRONJOB_NAME
  namespace: $NAMESPACE
spec:
  schedule: \"*/5 * * * *\"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: hello
            image: busybox
            command: [\"/bin/sh\", \"-c\", \"date; echo Hello\"]
          restartPolicy: OnFailure
EOF

# Modify cronjob
kubectl patch cronjob $CRONJOB_NAME -n $NAMESPACE -p '{\"spec\":{\"schedule\":\"*/10 * * * *\"}}' && \

# Delete cronjob
kubectl delete cronjob $CRONJOB_NAME -n $NAMESPACE"
run_test "Create, Modify, and Delete CronJob" "$cronjob_test"

# 6. Create and Modify Admission Webhook
webhook_test="
# Create webhook configuration
cat << EOF | kubectl apply -f -
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: $WEBHOOK_NAME
webhooks:
- name: webhook.example.com
  clientConfig:
    url: \"https://example.com/webhook\"
  rules:
  - apiGroups: [\"\"]
    apiVersions: [\"v1\"]
    operations: [\"CREATE\"]
    resources: [\"pods\"]
  admissionReviewVersions: [\"v1\"]
  sideEffects: None
EOF

# Modify webhook
kubectl patch mutatingwebhookconfiguration $WEBHOOK_NAME --type=json \
    -p='[{\"op\": \"replace\", \"path\": \"/webhooks/0/clientConfig/url\", \"value\":\"https://example2.com/webhook\"}]' && \

# Delete webhook
kubectl delete mutatingwebhookconfiguration $WEBHOOK_NAME"
run_test "Create, Modify, and Delete Admission Webhook" "$webhook_test"

# 7. Test Container Execution
container_exec_test="
# Create test pod
kubectl run test-pod --image=nginx -n $NAMESPACE && \
sleep 10 && \
kubectl exec -it test-pod -n $NAMESPACE -- ls / && \
kubectl delete pod test-pod -n $NAMESPACE"
run_test "Test Container Execution" "$container_exec_test"

# 8. Test Audit Log Generation
audit_log_test="
# Wait for logs to be available
sleep 30 && \
gcloud logging read 'resource.type=k8s_cluster AND \
    resource.labels.cluster_name=$CLUSTER_NAME' \
    --project=$PROJECT_ID \
    --limit=10"
run_test "Audit Log Generation" "$audit_log_test"

# Cleanup
echo "Performing cleanup..."
cleanup_command="
# Delete namespace
kubectl delete namespace $NAMESPACE --ignore-not-found

# Delete cluster
gcloud container clusters delete $CLUSTER_NAME \
    --zone $ZONE \
    --project $PROJECT_ID \
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

# Print important notes
echo
echo "Important Notes:"
echo "1. Some operations might take time to propagate in the cluster"
echo "2. Cluster creation and deletion can take several minutes"
echo "3. Audit logs might have some delay before appearing"

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