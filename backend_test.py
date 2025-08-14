import requests
import sys
import json
from datetime import datetime

class ShadowAIHunterAPITester:
    def __init__(self, base_url="http://localhost:8001"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.session = requests.Session()
        self.session.timeout = 10

    def run_test(self, name, method, endpoint, expected_status, data=None, params=None):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {method} {url}")
        
        try:
            if method == 'GET':
                response = self.session.get(url, headers=headers, params=params)
            elif method == 'POST':
                response = self.session.post(url, json=data, headers=headers)
            elif method == 'PUT':
                response = self.session.put(url, json=data, headers=headers)
            elif method == 'DELETE':
                response = self.session.delete(url, headers=headers)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    print(f"   Response: {json.dumps(response_data, indent=2)[:200]}...")
                    return True, response_data
                except:
                    return True, response.text
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                print(f"   Response: {response.text[:200]}...")
                return False, {}

        except requests.exceptions.RequestException as e:
            print(f"❌ Failed - Network Error: {str(e)}")
            return False, {}
        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_health_check(self):
        """Test health endpoint"""
        return self.run_test(
            "Health Check",
            "GET",
            "api/health",
            200
        )

    def test_populate_demo_data(self):
        """Test demo data population"""
        return self.run_test(
            "Populate Demo Data",
            "GET",
            "api/demo/populate",
            200
        )

    def test_dashboard_stats(self):
        """Test dashboard statistics"""
        success, response = self.run_test(
            "Dashboard Statistics",
            "GET",
            "api/dashboard/stats",
            200
        )
        
        if success and response:
            # Validate expected fields
            expected_fields = ['total_devices', 'high_risk_devices', 'active_threats', 'compliance_score']
            for field in expected_fields:
                if field not in response:
                    print(f"⚠️  Warning: Missing field '{field}' in dashboard stats")
                else:
                    print(f"   ✓ {field}: {response[field]}")
        
        return success, response

    def test_get_devices(self):
        """Test get devices endpoint"""
        success, response = self.run_test(
            "Get Network Devices",
            "GET",
            "api/devices",
            200
        )
        
        if success and response and 'devices' in response:
            devices = response['devices']
            print(f"   Found {len(devices)} devices")
            for i, device in enumerate(devices[:3]):  # Show first 3 devices
                print(f"   Device {i+1}: {device.get('hostname', 'Unknown')} ({device.get('ip_address', 'No IP')}) - Risk: {device.get('ai_risk_score', 0)}")
        
        return success, response

    def test_get_alerts(self):
        """Test get alerts endpoint"""
        success, response = self.run_test(
            "Get Security Alerts",
            "GET",
            "api/alerts",
            200
        )
        
        if success and response and 'alerts' in response:
            alerts = response['alerts']
            print(f"   Found {len(alerts)} alerts")
            for i, alert in enumerate(alerts[:3]):  # Show first 3 alerts
                print(f"   Alert {i+1}: {alert.get('title', 'Unknown')} - Severity: {alert.get('severity', 'Unknown')}")
        
        return success, response

    def test_get_policies(self):
        """Test get policies endpoint"""
        success, response = self.run_test(
            "Get Security Policies",
            "GET",
            "api/policies",
            200
        )
        
        if success and response and 'policies' in response:
            policies = response['policies']
            print(f"   Found {len(policies)} policies")
            for i, policy in enumerate(policies[:2]):  # Show first 2 policies
                print(f"   Policy {i+1}: {policy.get('name', 'Unknown')} - Type: {policy.get('rule_type', 'Unknown')}")
        
        return success, response

    def test_network_scan(self):
        """Test network scan initiation"""
        scan_data = {
            "network_range": "192.168.1.0/24",
            "scan_type": "comprehensive",
            "deep_scan": True
        }
        
        success, response = self.run_test(
            "Initiate Network Scan",
            "POST",
            "api/scan",
            200,
            data=scan_data
        )
        
        if success and response:
            scan_id = response.get('scan_id')
            if scan_id:
                print(f"   Scan initiated with ID: {scan_id}")
            else:
                print("   ⚠️  Warning: No scan_id returned")
        
        return success, response

    def test_create_policy(self):
        """Test policy creation"""
        policy_data = {
            "name": "Test AI Detection Policy",
            "description": "Test policy for AI service detection",
            "rule_type": "monitor",
            "conditions": {"ai_services": ["test-ai-service"]},
            "actions": ["log_activity"],
            "enabled": True
        }
        
        return self.run_test(
            "Create Security Policy",
            "POST",
            "api/policies",
            200,
            data=policy_data
        )

def main():
    print("🚀 Starting Shadow AI Hunter API Tests")
    print("=" * 50)
    
    # Initialize tester
    tester = ShadowAIHunterAPITester("http://localhost:8001")
    
    # Test sequence
    tests = [
        ("Health Check", tester.test_health_check),
        ("Populate Demo Data", tester.test_populate_demo_data),
        ("Dashboard Statistics", tester.test_dashboard_stats),
        ("Get Devices", tester.test_get_devices),
        ("Get Alerts", tester.test_get_alerts),
        ("Get Policies", tester.test_get_policies),
        ("Network Scan", tester.test_network_scan),
        ("Create Policy", tester.test_create_policy),
    ]
    
    # Run all tests
    for test_name, test_func in tests:
        try:
            test_func()
        except Exception as e:
            print(f"❌ Test '{test_name}' failed with exception: {str(e)}")
    
    # Print final results
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {tester.tests_passed}/{tester.tests_run} tests passed")
    
    if tester.tests_passed == tester.tests_run:
        print("🎉 All tests passed! Backend API is working correctly.")
        return 0
    else:
        failed_tests = tester.tests_run - tester.tests_passed
        print(f"⚠️  {failed_tests} test(s) failed. Please check the backend implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())