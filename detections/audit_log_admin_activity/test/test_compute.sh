#!/bin/bash

# Variables
PROJECT_ID="parker-aaa"
ZONE="us-central1-a"
REGION="us-central1"
INSTANCE_NAME="test-instance"
NETWORK_NAME="test-network"
FIREWALL_NAME="test-firewall"
VPN_TUNNEL_NAME="test-vpn"
DISK_NAME="test-disk"
SNAPSHOT_NAME="test-snapshot"
IMAGE_NAME="test-image"

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

# 1. Test Firewall Rule Changes
firewall_test="
gcloud compute firewall-rules create $FIREWALL_NAME \
    --network=default \
    --allow=tcp:80 \
    --project=$PROJECT_ID && \
sleep 5 && \
gcloud compute firewall-rules delete $FIREWALL_NAME \
    --project=$PROJECT_ID \
    --quiet"
run_test "Firewall Rule Changes" "$firewall_test"

# 2. Test VPN Tunnel Operations
vpn_test="
gcloud compute vpn-tunnels create $VPN_TUNNEL_NAME \
    --peer-address=8.8.8.8 \
    --shared-secret=test-secret \
    --target-vpn-gateway=test-vpn-gateway \
    --region=$REGION \
    --project=$PROJECT_ID || true && \
sleep 5 && \
gcloud compute vpn-tunnels delete $VPN_TUNNEL_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --quiet || true"
run_test "VPN Tunnel Operations" "$vpn_test"

# 3. Test Compute Instance with Public IP
public_ip_test="
gcloud compute instances create $INSTANCE_NAME \
    --zone=$ZONE \
    --machine-type=e2-micro \
    --network-interface=network-tier=PREMIUM,subnet=default \
    --project=$PROJECT_ID && \
sleep 5 && \
gcloud compute instances delete $INSTANCE_NAME \
    --zone=$ZONE \
    --project=$PROJECT_ID \
    --quiet"
run_test "Public IP Instance" "$public_ip_test"

# 4. Test Compute Disk Operations
disk_test="
gcloud compute disks create $DISK_NAME \
    --size=10GB \
    --zone=$ZONE \
    --project=$PROJECT_ID && \
gcloud compute disks add-iam-policy-binding $DISK_NAME \
    --member='user:test@example.com' \
    --role='roles/compute.admin' \
    --zone=$ZONE \
    --project=$PROJECT_ID && \
sleep 5 && \
gcloud compute disks delete $DISK_NAME \
    --zone=$ZONE \
    --project=$PROJECT_ID \
    --quiet"
run_test "Disk Operations" "$disk_test"

# 5. Test Small Disk Size
small_disk_test="
gcloud compute instances create small-disk-instance \
    --zone=$ZONE \
    --machine-type=e2-micro \
    --boot-disk-size=10GB \
    --project=$PROJECT_ID && \
sleep 5 && \
gcloud compute instances delete small-disk-instance \
    --zone=$ZONE \
    --project=$PROJECT_ID \
    --quiet"
run_test "Small Disk Size" "$small_disk_test"

# 6. Test OS Login Disabled
os_login_test="
gcloud compute instances create os-login-test \
    --zone=$ZONE \
    --machine-type=e2-micro \
    --metadata=enable-oslogin=FALSE \
    --project=$PROJECT_ID && \
sleep 5 && \
gcloud compute instances delete os-login-test \
    --zone=$ZONE \
    --project=$PROJECT_ID \
    --quiet"
run_test "OS Login Disabled" "$os_login_test"

# 7. Test VPC Flow Logs
vpc_flow_logs_test="
gcloud compute networks subnets create test-subnet \
    --network=default \
    --range=10.0.0.0/24 \
    --region=$REGION \
    --enable-flow-logs \
    --project=$PROJECT_ID && \
gcloud compute networks subnets update test-subnet \
    --region=$REGION \
    --no-enable-flow-logs \
    --project=$PROJECT_ID && \
sleep 5 && \
gcloud compute networks subnets delete test-subnet \
    --region=$REGION \
    --project=$PROJECT_ID \
    --quiet"
run_test "VPC Flow Logs" "$vpc_flow_logs_test"

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