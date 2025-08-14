import argparse
from crawler import scan_network
from risk_analyzer import analyze_risks, simulate_what_if
from dashboard import visualize_risks
from policy_enforcer import enforce_policies
from siem_integrator import send_alert
from gamifier import gamify_audit

def main():
    parser = argparse.ArgumentParser(description="Shadow AI Hunter Tool")
    parser.add_argument('--scan', action='store_true', help='Scan network')
    parser.add_argument('--network', type=str, help='Network CIDR to scan, e.g., 192.168.1.0/24')
    parser.add_argument('--dashboard', action='store_true', help='Visualize risks')
    parser.add_argument('--enforce', action='store_true', help='Enforce policies')
    parser.add_argument('--gamify', action='store_true', help='Gamify audit')
    parser.add_argument('--scenario', type=str, help='Scenario for simulation, e.g., data_leak')
    args = parser.parse_args()

    if args.scan and args.network:
        devices = scan_network(args.network)
        risks = analyze_risks(devices)
        print(f"Detected risks: {risks}")
        if args.enforce:
            enforce_policies(risks)
        send_alert(risks)  # Mock SIEM alert

    if args.gamify and args.scenario:
        score = gamify_audit(args.scenario)
        print(f"Audit game score: {score}")

    if args.dashboard:
        visualize_risks({})  # Pass real data in production

if __name__ == "__main__":
    main()
