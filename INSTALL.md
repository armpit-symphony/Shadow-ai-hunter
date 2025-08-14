# Shadow AI Hunter - Installation Guide

## Quick Start (Plug & Play) 🚀

### Option 1: One-Command Start (Recommended)
```bash
# Make start script executable and run
chmod +x start.sh
./start.sh
```

That's it! The script will:
- ✅ Check system requirements
- ✅ Set up the environment  
- ✅ Start all services with Docker
- ✅ Load demo data
- ✅ Open the dashboard at http://localhost

### Option 2: Docker Compose
```bash
# Start all services
docker-compose up -d

# Load demo data
curl -X GET "http://localhost:8001/api/demo/populate"

# Access at http://localhost
```

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
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python server.py
```

### Frontend Setup  
```bash
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