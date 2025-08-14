// MongoDB initialization script
print('Starting MongoDB initialization...');

// Switch to shadow_ai_hunter database
db = db.getSiblingDB('shadow_ai_hunter');

// Create collections with proper indexing
db.createCollection('devices');
db.createCollection('scans');
db.createCollection('alerts');
db.createCollection('policies');
db.createCollection('users');

// Create indexes for better performance
db.devices.createIndex({ "ip_address": 1 }, { unique: true });
db.devices.createIndex({ "ai_risk_score": -1 });
db.devices.createIndex({ "last_seen": -1 });

db.scans.createIndex({ "timestamp": -1 });
db.scans.createIndex({ "status": 1 });

db.alerts.createIndex({ "created_at": -1 });
db.alerts.createIndex({ "severity": 1 });
db.alerts.createIndex({ "resolved": 1 });
db.alerts.createIndex({ "device_ip": 1 });

db.policies.createIndex({ "name": 1 }, { unique: true });
db.policies.createIndex({ "rule_type": 1 });
db.policies.createIndex({ "enabled": 1 });

// Insert sample data for demonstration
print('Inserting sample data...');

// Sample policies
db.policies.insertMany([
    {
        "name": "Block Unauthorized AI APIs",
        "description": "Automatically block access to unauthorized AI services like OpenAI, Claude, etc.",
        "rule_type": "block",
        "conditions": {
            "ai_services": ["openai-api", "claude-api", "bard-api"],
            "risk_threshold": 0.7
        },
        "actions": ["block_network", "send_alert", "log_incident"],
        "enabled": true,
        "created_at": new Date(),
        "priority": "high"
    },
    {
        "name": "Monitor Development Tools",
        "description": "Monitor usage of AI-powered development tools",
        "rule_type": "monitor",
        "conditions": {
            "ai_services": ["github-copilot", "codeium", "tabnine"],
            "device_types": ["workstation", "laptop"]
        },
        "actions": ["send_alert", "log_activity"],
        "enabled": true,
        "created_at": new Date(),
        "priority": "medium"
    },
    {
        "name": "High Risk Device Alert",
        "description": "Alert on devices with AI risk score above 0.8",
        "rule_type": "alert",
        "conditions": {
            "ai_risk_score": { "$gte": 0.8 }
        },
        "actions": ["send_alert", "quarantine_review"],
        "enabled": true,
        "created_at": new Date(),
        "priority": "high"
    }
]);

// Sample devices
db.devices.insertMany([
    {
        "ip_address": "192.168.1.100",
        "hostname": "ceo-laptop",
        "device_type": "laptop",
        "operating_system": "Windows 11",
        "ai_risk_score": 0.95,
        "ai_services_detected": ["openai-gpt4", "claude-3-opus", "midjourney", "chatgpt-plus"],
        "last_seen": new Date(),
        "first_detected": new Date(Date.now() - 7*24*60*60*1000),
        "status": "active",
        "location": "Executive Floor",
        "user": "John CEO",
        "compliance_violations": ["unauthorized_ai_usage", "data_privacy_risk"],
        "blocked_attempts": 15
    },
    {
        "ip_address": "192.168.1.150",
        "hostname": "dev-workstation-01",
        "device_type": "workstation",
        "operating_system": "Ubuntu 22.04",
        "ai_risk_score": 0.75,
        "ai_services_detected": ["github-copilot", "codeium", "openai-api"],
        "last_seen": new Date(),
        "first_detected": new Date(Date.now() - 14*24*60*60*1000),
        "status": "active",
        "location": "Engineering",
        "user": "Alice Developer",
        "compliance_violations": ["unapproved_tools"],
        "blocked_attempts": 5
    },
    {
        "ip_address": "192.168.1.200",
        "hostname": "ml-server-prod",
        "device_type": "server",
        "operating_system": "CentOS 8",
        "ai_risk_score": 0.85,
        "ai_services_detected": ["tensorflow-serving", "huggingface-transformers", "pytorch", "openai-embeddings"],
        "last_seen": new Date(),
        "first_detected": new Date(Date.now() - 30*24*60*60*1000),
        "status": "active",
        "location": "Data Center",
        "user": "System",
        "compliance_violations": ["model_governance"],
        "blocked_attempts": 0
    },
    {
        "ip_address": "192.168.1.75",
        "hostname": "marketing-laptop",
        "device_type": "laptop",
        "operating_system": "macOS Sonoma",
        "ai_risk_score": 0.65,
        "ai_services_detected": ["canva-ai", "jasper-ai", "copy-ai"],
        "last_seen": new Date(Date.now() - 2*60*60*1000),
        "first_detected": new Date(Date.now() - 5*24*60*60*1000),
        "status": "inactive",
        "location": "Marketing",
        "user": "Bob Marketer",
        "compliance_violations": ["content_generation_risk"],
        "blocked_attempts": 2
    }
]);

// Sample alerts
db.alerts.insertMany([
    {
        "title": "CRITICAL: Executive Using Unauthorized AI Services",
        "description": "CEO laptop detected accessing multiple high-risk AI services including GPT-4 and Claude-3. Potential data exfiltration risk.",
        "severity": "critical",
        "device_ip": "192.168.1.100",
        "device_hostname": "ceo-laptop",
        "alert_type": "policy_violation",
        "rule_triggered": "Block Unauthorized AI APIs",
        "created_at": new Date(),
        "resolved": false,
        "assigned_to": "security-team",
        "impact_score": 9.5,
        "evidence": {
            "api_calls": 47,
            "data_uploaded": "2.3 GB",
            "time_spent": "3.5 hours"
        }
    },
    {
        "title": "HIGH: Unauthorized AI Development Tools",
        "description": "Development workstation using GitHub Copilot and Codeium without proper licensing approval.",
        "severity": "high",
        "device_ip": "192.168.1.150",
        "device_hostname": "dev-workstation-01",
        "alert_type": "licensing_violation",
        "rule_triggered": "Monitor Development Tools",
        "created_at": new Date(Date.now() - 2*60*60*1000),
        "resolved": false,
        "assigned_to": "it-compliance",
        "impact_score": 7.2
    },
    {
        "title": "MEDIUM: ML Server Model Governance Issue",
        "description": "Production ML server detected using unregistered models and external API integrations.",
        "severity": "medium",
        "device_ip": "192.168.1.200",
        "device_hostname": "ml-server-prod",
        "alert_type": "governance_violation",
        "rule_triggered": "High Risk Device Alert",
        "created_at": new Date(Date.now() - 6*60*60*1000),
        "resolved": true,
        "resolved_at": new Date(Date.now() - 1*60*60*1000),
        "assigned_to": "ml-ops-team",
        "impact_score": 6.8
    },
    {
        "title": "LOW: Marketing AI Tool Usage",
        "description": "Marketing laptop using AI content generation tools. Monitor for brand consistency.",
        "severity": "low",
        "device_ip": "192.168.1.75",
        "device_hostname": "marketing-laptop",
        "alert_type": "monitoring",
        "rule_triggered": "Monitor Development Tools",
        "created_at": new Date(Date.now() - 24*60*60*1000),
        "resolved": true,
        "resolved_at": new Date(Date.now() - 20*60*60*1000),
        "assigned_to": "marketing-lead",
        "impact_score": 3.2
    }
]);

// Sample scan records
db.scans.insertMany([
    {
        "network_range": "192.168.1.0/24",
        "scan_type": "comprehensive",
        "deep_scan": true,
        "status": "completed",
        "timestamp": new Date(),
        "completed_at": new Date(Date.now() - 30*1000),
        "devices_found": 4,
        "ai_services_detected": 12,
        "high_risk_devices": 3,
        "scan_duration": "45 seconds",
        "scanner_version": "2.0.1"
    },
    {
        "network_range": "10.0.0.0/16",
        "scan_type": "basic",
        "deep_scan": false,
        "status": "completed",
        "timestamp": new Date(Date.now() - 24*60*60*1000),
        "completed_at": new Date(Date.now() - 24*60*60*1000 + 15*1000),
        "devices_found": 12,
        "ai_services_detected": 8,
        "high_risk_devices": 2,
        "scan_duration": "15 seconds",
        "scanner_version": "2.0.1"
    }
]);

print('MongoDB initialization completed successfully!');
print('- Created collections: devices, scans, alerts, policies, users');
print('- Created indexes for optimal performance');
print('- Inserted sample data for demonstration');
print('Database ready for Shadow AI Hunter application.');