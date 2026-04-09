# Shadow AI Hunter - Installation Guide

## Quick Start (Plug & Play) 🚀

### Prerequisites
- Docker 20.0+, Docker Compose 2.0+
- **Node 18** (for local frontend builds — the frontend Dockerfile uses `node:18-alpine`; see `.nvmrc`)
- 8 GB RAM minimum (16 GB recommended)
- Ports 80, 443, 3000, 8001, 27017, 6379 available

### Step 1: Create .env file (required)
```bash
cp .env.example .env   # if .env.example exists
# OR create manually with required vars below
```

**Required environment variables:**
```bash
# Security (MUST be set — app will fail to start without these)
JWT_SECRET_KEY=your-random-256-bit-secret-here
SECRET_KEY=your-random-256-bit-secret-here

# Database credentials (MUST be set)
MONGO_PASSWORD=your-mongo-password-here
REDIS_PASSWORD=your-redis-password-here

# Default admin credentials (change these before any deployment)
DEFAULT_ADMIN_PASSWORD=change-this-admin-password
DEFAULT_ANALYST_PASSWORD=change-this-analyst-password

# Optional: set these explicitly for clarity
MONGO_URL=mongodb://admin:${MONGO_PASSWORD}@localhost:27017/shadow_ai_hunter?authSource=admin
REDIS_URL=redis://:${REDIS_PASSWORD}@localhost:6379/0

# Frontend
REACT_APP_BACKEND_URL=http://localhost:8001
```

Generate a strong secret:
```bash
openssl rand -hex 32
```

### Step 2: Start services
```bash
docker-compose up -d
docker-compose ps   # verify all services are healthy
```

### Step 3: Check service health
```bash
# Backend should respond
curl -s http://localhost:8001/api/health | head -3

# Frontend should be up
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000

# All containers healthy
docker-compose ps
```

### Step 4: Seed default users
```bash
curl -X GET "http://localhost:8001/api/demo/populate" 2>/dev/null ||   echo "Demo populate unavailable in production mode"
```

### Step 5: Log in
- URL: http://localhost:3000
- Admin: `admin` / password from `DEFAULT_ADMIN_PASSWORD`
- Analyst: `analyst` / password from `DEFAULT_ANALYST_PASSWORD`

### Step 6: Submit a test scan
1. Log in and go to **Network Scan** (sidebar)
2. Enter a network range (e.g. `192.168.1.0/24` or `10.0.0.0/24`)
3. Click **Start Scan** — scan is queued and processed by the worker
4. Watch live progress via WebSocket, or go to **Scan Detail** to look up by ID
5. Generate a report from the **Scan Detail** page after completion

---

### Migration Notes: Legacy vs. Orchestrated Endpoints

This release introduces a new **orchestrated job model** (Phase 3) while preserving all legacy endpoints for backwards compatibility.

| Operation | New (Orchestrated) | Legacy Fallback |
|-----------|-------------------|-----------------|
| Create scan | `POST /scan` | `POST /api/scan` |
| List scans | `GET /scans` | `GET /api/scans` |
| Get scan | `GET /scan/{id}` | `GET /api/scans/{id}` |
| Get report | `GET /reports/{id}` | `POST /api/reports/generate` |

**Frontend behaviour:** The React app automatically uses the new endpoints where available and falls back to legacy endpoints when needed. No action required from users.

**For future migration:** Legacy endpoints will be removed once all clients use the orchestrated API. The `/api/` prefix is the signal to identify legacy routes.


## System Requirements

### Minimum Requirements
- **OS**: Linux, macOS, or Windows with WSL2
- **RAM**: 8GB (16GB recommended)
- **Storage**: 10GB free space
- **Docker**: Version 20.0+
- **Docker Compose**: Version 2.0+

### For Network Scanning
- **Permissions**: Root/Administrator access
- **Network**: Access to scan target networks
- **Ports**: 80, 443, 3000, 8001, 27017

## Manual Installation

### Backend Setup
```bash
cd backend
python3 -m venv ../.venv
source ../.venv/bin/activate  # Windows: ..\.venv\Scripts\activate
pip install -r requirements.txt -r ../requirements-dev.txt
python server.py
```

### Frontend Setup (Node 18 required)
```bash
# Use Node 18 (see .nvmrc for exact version)
# If using nvm: nvm install 18 && nvm use 18
node --version  # confirm v18.x.x

cd frontend
yarn install  # or npm install
yarn start    # or npm start
```

### Database Setup
```bash
# Start MongoDB
mongod --dbpath ./data

# Initialize with sample data
mongosh shadow_ai_hunter < scripts/mongo-init.js
```

## Configuration

### Environment Variables
```bash
# Backend (.env)
MONGO_URL=mongodb://localhost:27017/shadow_ai_hunter
SECRET_KEY=your-secret-key-here
SCAN_NETWORK_RANGE=192.168.1.0/24
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

# Frontend (.env)
REACT_APP_BACKEND_URL=http://localhost:8001
```

### Network Permissions
For network scanning to work properly:

**Linux/macOS:**
```bash
sudo ./start.sh
```

**Windows:**
```bash
# Run PowerShell as Administrator
.\start.ps1
```

## Troubleshooting

### Python 3.12 Dependency Notes
If you're on Python 3.12, use the project venv at `./.venv` and the pinned
dependencies in `backend/requirements.txt`. These pins include compatible
versions of `numpy` and `torch`.

### Port Conflicts
If ports are already in use:
```bash
# Check what's using the ports
netstat -tulpn | grep ':80\|:3000\|:8001\|:27017'

# Stop conflicting services or change ports in docker-compose.yml
```

### Permission Issues
```bash
# Fix file permissions
chmod +x start.sh stop.sh
sudo chown -R $USER:$USER .

# For network scanning
sudo setcap 'cap_net_admin,cap_net_raw+eip' /usr/bin/python3
```

### MongoDB Connection Issues
```bash
# Check MongoDB status
docker-compose logs mongodb

# Reset MongoDB data
docker-compose down -v
docker-compose up -d mongodb
```

### Memory Issues
```bash
# Check available memory
free -h

# Reduce Docker memory usage
docker system prune -f
```

## Production Deployment

### SSL/TLS Configuration
```bash
# Generate SSL certificates
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem

# Update nginx configuration
# Edit nginx/nginx.conf to enable SSL
```

### Security Hardening
```bash
# Change default passwords
# Update .env files with secure credentials

# Configure firewall
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Set up log rotation
sudo logrotate -d logs/shadow-ai.conf
```

### Scaling & Performance
```bash
# Horizontal scaling
docker-compose up -d --scale backend=3

# Monitor performance
docker stats
docker-compose logs -f backend
```

## Updates & Maintenance

### Updating Shadow AI Hunter
```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose up -d --build
```

### Backup & Recovery
```bash
# Backup MongoDB data
docker-compose exec mongodb mongodump --out /backup

# Backup configuration
tar -czf shadow-ai-backup.tar.gz .env docker-compose.yml nginx/

# Restore
docker-compose exec mongodb mongorestore /backup
```

## Support

- 📖 **Documentation**: [docs.shadowai.com](https://docs.shadowai.com)
- 💬 **Community**: [GitHub Discussions](https://github.com/your-org/shadow-ai-hunter/discussions)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/your-org/shadow-ai-hunter/issues)
- 📧 **Enterprise Support**: support@shadowai.com
