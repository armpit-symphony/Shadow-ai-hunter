# Shadow AI Hunter - Enterprise AI Detection Platform

> **⚠️ Current Status (v2.0.0)**: This is a **prototype/demo**. Many features below are planned for V1/V2. See [Roadmap](#-roadmap) for delivery timeline.

<div align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Docker-Ready-blue.svg" alt="Docker">
  <img src="https://img.shields.io/badge/Python-3.11+-yellow.svg" alt="Python">
  <img src="https://img.shields.io/badge/React-18+-61dafb.svg" alt="React">
</div>

## 🔍 Overview

Shadow AI Hunter is a comprehensive enterprise security platform designed to detect, monitor, and manage unauthorized AI usage across your organization's network infrastructure. It combines advanced network scanning, machine learning-based detection, and real-time monitoring to protect against AI-related security risks and compliance violations.

### 🚨 Why Shadow AI Hunter?

- **Hidden AI Risks**: 73% of enterprises have shadow AI usage they're unaware of
- **Compliance Violations**: Unauthorized AI tools can lead to GDPR, HIPAA, and SOX violations
- **Data Exfiltration**: AI services often upload sensitive data to external servers
- **Cost Control**: Unmanaged AI subscriptions can cost organizations thousands monthly
- **Security Blind Spots**: Traditional security tools don't detect AI usage patterns

## ✨ Key Features

### 🔍 **AI-Powered Network Scanning**
- Real-time network discovery and device fingerprinting
- ML-based traffic analysis for AI service detection
- Comprehensive port scanning and service identification
- Cloud AI service detection (AWS, Azure, GCP AI services)

### 📊 **Risk Visualization Dashboard**
- Interactive web-based security dashboard
- Real-time threat monitoring and alerting
- Risk scoring and compliance tracking
- Network topology visualization
- Executive reporting and analytics

### 🛡️ **Automated Policy Enforcement**
- Rule-based blocking of unauthorized AI services
- Integration with firewalls and network security appliances
- Quarantine capabilities for high-risk devices
- Automated incident response workflows

### 🔗 **Enterprise Integrations**
- **SIEM Integration**: Splunk, ELK Stack, QRadar, ArcSight
- **Ticketing Systems**: Jira, ServiceNow, PagerDuty
- **Communication**: Slack, Microsoft Teams, Email alerts
- **Network Security**: Palo Alto, Fortinet, Cisco ASA

### 🎮 **Gamified Security Audits**
- AI-simulated "what-if" breach scenarios
- Interactive security training modules  
- Compliance scoring and leaderboards
- Incident response simulation games

## 🚀 Quick Start

### Method 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/shadow-ai-hunter.git
cd shadow-ai-hunter

# Start all services
docker-compose up -d

# Access the application
open http://localhost
```

### Method 2: Manual Installation

```bash
# Backend setup
cd backend
python3 -m venv ../.venv
source ../.venv/bin/activate  # Windows: ..\.venv\Scripts\activate
pip install -r requirements.txt -r ../requirements-dev.txt
python server.py

# Frontend setup (new terminal)
cd frontend  
yarn install
yarn start

# MongoDB (new terminal)
mongod --dbpath ./data
```

## 📋 System Requirements

### Minimum Requirements
- **OS**: Linux (Ubuntu 20.04+), macOS, Windows 10+
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 20GB free space
- **Network**: Administrative access for network scanning
- **Python**: 3.11 or higher
- **Python 3.12**: Supported via pinned deps in `backend/requirements.txt`
- **Node.js**: 18 or higher
- **MongoDB**: 5.0 or higher

### For Enterprise Deployment
- **CPU**: 8+ cores for large network scanning
- **RAM**: 32GB+ for real-time analysis
- **Storage**: SSD with 100GB+ for log retention
- **Network**: Multiple network interface support
- **GPU**: Optional CUDA support for ML acceleration

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React UI      │    │   FastAPI       │    │   MongoDB       │
│   Dashboard     │◄──►│   Backend       │◄──►│   Database      │
│   (Port 3000)   │    │   (Port 8001)   │    │   (Port 27017)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
         ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
         │    Nginx        │    │   Network       │    │     SIEM        │
         │  Load Balancer  │    │   Scanner       │    │  Integration    │
         │   (Port 80)     │    │   Engine        │    │   (External)    │
         └─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔧 Configuration

### Environment Variables

**Backend (.env)**
```env
MONGO_URL=mongodb://localhost:27017/shadow_ai_hunter
SECRET_KEY=your-super-secret-key
ACCESS_TOKEN_EXPIRE_MINUTES=30
SCAN_NETWORK_RANGE=192.168.1.0/24
ENABLE_DEEP_SCAN=true
SIEM_WEBHOOK_URL=https://your-siem.com/webhook
COOKIE_SECURE=false  # set true in production (HTTPS)
CSRF_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
SEGMENT_MAP=corp:10.0.0.0/24;lab:10.0.1.0/24
EVENT_TTL_DAYS=30
WS_EVENT_TTL_HOURS=6
AUDIT_TTL_DAYS=365
SUPER_ADMIN_USERS=admin
REPORT_MASK_PII=false
SIEM_RETRY_MAX=3
SIEM_RETRY_INTERVALS=10,30,60
```

**Frontend (.env)**
```env
REACT_APP_BACKEND_URL=http://localhost:8001
GENERATE_SOURCEMAP=false
REACT_APP_ENABLE_DEMO_MODE=true
```

### Network Scanning Configuration

```yaml
# config/scanner.yaml
network_ranges:
  - "192.168.1.0/24"
  - "10.0.0.0/16"
  - "172.16.0.0/12"

scan_settings:
  ports: [22, 80, 443, 3000, 8080, 8000, 11434]  # Common AI service ports
  timeout: 30
  max_concurrent: 100
  deep_scan_enabled: true
  
ai_signatures:
  openai:
    domains: ["api.openai.com", "chat.openai.com"]
    ports: [443]
    headers: ["authorization: bearer sk-"]
  
  anthropic:
    domains: ["api.anthropic.com"]
    ports: [443]
    headers: ["x-api-key: sk-ant-"]
```

## 📊 Usage Examples

### Starting a Network Scan
```python
import requests

# Trigger comprehensive scan
response = requests.post("http://localhost:8001/api/scan", json={
    "network_range": "192.168.1.0/24",
    "scan_type": "comprehensive", 
    "deep_scan": True
})

print(f"Scan initiated: {response.json()['scan_id']}")
```

### Admin Metrics
```bash
curl -H "Authorization: Bearer <admin_token>" http://localhost:8001/api/metrics
```

### Creating Security Policies
```python
# Create AI blocking policy
policy = {
    "name": "Block ChatGPT Access",
    "description": "Block all access to OpenAI ChatGPT",
    "rule_type": "block",
    "conditions": {
        "domains": ["chat.openai.com"],
        "risk_threshold": 0.8
    },
    "actions": ["block_network", "send_alert"]
}

requests.post("http://localhost:8001/api/policies", json=policy)
```

### Real-time Monitoring
```javascript
// WebSocket connection for real-time updates
const ws = new WebSocket('ws://localhost:8001/api/ws');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'new_threat') {
        console.log('New threat detected:', data.device_ip);
        showAlert(data.alert);
    }
};
```

## 🔐 Security Features

### Network Security
- Encrypted communication (TLS 1.3)
- API rate limiting and DDoS protection
- Secure credential storage
- Network segmentation support

### Compliance & Auditing
- **GDPR**: Data processing transparency
- **HIPAA**: Healthcare data protection monitoring
- **SOX**: Financial compliance reporting  
- **ISO 27001**: Security management integration
- Audit trail logging and retention

### Access Control
- Role-based access control (RBAC)
- Multi-factor authentication (MFA)
- SSO integration (SAML, OAuth)
- Session management and timeout

## 🔌 Enterprise Integrations

### SIEM Platforms
```python
# Splunk Integration
splunk_config = {
    "host": "splunk.company.com",
    "port": 8089,
    "token": "your-hec-token",
    "index": "security"
}

# Send alert to Splunk
send_to_siem("splunk", alert_data, splunk_config)
```

### Communication Platforms
```yaml
# Slack notifications
slack:
  webhook_url: "https://hooks.slack.com/services/..."
  channel: "#security-alerts"
  username: "ShadowAI-Bot"

# Microsoft Teams
teams:
  webhook_url: "https://company.webhook.office.com/..."
  card_format: "adaptive"
```

## 📈 Performance & Scaling

### Monitoring Metrics
- Scan performance (devices/minute)
- Detection accuracy rates
- False positive/negative rates
- System resource utilization
- Network bandwidth usage

### Scaling Recommendations
- **Small Org** (< 500 devices): Single server deployment
- **Medium Org** (500-5000 devices): Load-balanced cluster
- **Large Enterprise** (5000+ devices): Distributed scanning nodes

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/your-org/shadow-ai-hunter.git
cd shadow-ai-hunter

# Backend development
cd backend && pip install -r requirements-dev.txt
python -m pytest tests/

# Frontend development  
cd frontend && yarn install
yarn test
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs.shadowai.com](https://docs.shadowai.com)
- **Community Forum**: [community.shadowai.com](https://community.shadowai.com)  
- **Bug Reports**: [GitHub Issues](https://github.com/your-org/shadow-ai-hunter/issues)
- **Enterprise Support**: support@shadowai.com
- **Security Issues**: security@shadowai.com

## 🎯 Roadmap

### ✅ Currently Implemented (Prototype)
- Basic Flask backend with mock AI detection
- React dashboard (static UI)
- Docker Compose setup (MongoDB + Backend + Frontend + Nginx)
- Basic network scanning (socket-based, limited)

### Version 2.1 (Q1 2025)
- [ ] Cloud AI service detection (AWS Bedrock, Azure OpenAI)
- [ ] Advanced ML models for behavior analysis
- [ ] Mobile device scanning capabilities
- [ ] API rate limiting and quota management

### Version 2.2 (Q2 2025)  
- [ ] Zero-trust network integration
- [ ] Kubernetes deployment support
- [ ] Advanced reporting and analytics
- [ ] Multi-tenant architecture

### Version 3.0 (Q3 2025)
- [ ] AI-powered predictive threat modeling
- [ ] Automated remediation workflows
- [ ] Integration with major EDR platforms
- [ ] Advanced visualization and dashboards

---

<div align="center">

**Made with ❤️ by the Shadow AI Hunter Team**

[Website](https://shadowai.com) • [Documentation](https://docs.shadowai.com) • [Twitter](https://twitter.com/shadowaihunter)

</div>
