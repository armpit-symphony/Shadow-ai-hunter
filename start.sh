#!/bin/bash

# Shadow AI Hunter - Quick Start Script
# This script provides plug-and-play deployment for the Shadow AI Hunter platform

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Logo
echo -e "${PURPLE}"
cat << "EOF"
   _____ _               _               ___    _____ 
  / ____| |             | |             / _ \  |_   _|
 | (___ | |__   __ _  __| | _____      _| |_| |   | |  
  \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /|  _  |   | |  
  ____) | | | | (_| | (_| | (_) \ V  V / | | | |  _| |_ 
 |_____/|_| |_|\__,_|\__,_|\___/ \_/\_/  |_| |_| |_____|
                                                        
  _    _             _            
 | |  | |           | |           
 | |__| |_   _ _ __ | |_ ___ _ __ 
 |  __  | | | | '_ \| __/ _ \ '__|
 | |  | | |_| | | | | ||  __/ |   
 |_|  |_|\__,_|_| |_|\__\___|_|   
                                  
EOF
echo -e "${NC}"

echo -e "${BLUE}=== Shadow AI Hunter - Enterprise AI Detection Platform ===${NC}"
echo -e "${GREEN}Version 2.0.0 - Production Ready${NC}"
echo ""

# Check if running as root for network scanning capabilities
check_permissions() {
    echo -e "${YELLOW}🔍 Checking permissions...${NC}"
    if [[ $EUID -eq 0 ]]; then
        echo -e "${GREEN}✅ Running with root privileges - Network scanning enabled${NC}"
    else
        echo -e "${YELLOW}⚠️  Not running as root - Some network scanning features may be limited${NC}"
        echo "   For full functionality, run: sudo ./start.sh"
    fi
    echo ""
}

# Check system requirements
check_requirements() {
    echo -e "${YELLOW}📋 Checking system requirements...${NC}"
    
    # Check Docker
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}✅ Docker installed$(docker --version)${NC}"
    else
        echo -e "${RED}❌ Docker not found. Please install Docker first.${NC}"
        echo "   Ubuntu/Debian: curl -fsSL https://get.docker.com | sh"
        echo "   macOS: Download from https://docker.com"
        exit 1
    fi
    
    # Check Docker Compose
    if command -v docker-compose &> /dev/null; then
        echo -e "${GREEN}✅ Docker Compose installed$(docker-compose --version)${NC}"
    else
        echo -e "${RED}❌ Docker Compose not found. Please install Docker Compose first.${NC}"
        exit 1
    fi
    
    # Check available memory
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        MEMORY=$(free -m | awk 'NR==2{printf "%.1f GB", $2/1024}')
        echo -e "${GREEN}✅ Available Memory: $MEMORY${NC}"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        MEMORY=$(system_profiler SPHardwareDataType | grep "  Memory:" | awk '{print $2 $3}')
        echo -e "${GREEN}✅ Available Memory: $MEMORY${NC}"
    fi
    
    # Check available disk space
    DISK_SPACE=$(df -h . | awk 'NR==2 {print $4}')
    echo -e "${GREEN}✅ Available Disk Space: $DISK_SPACE${NC}"
    
    echo ""
}

# Setup environment
setup_environment() {
    echo -e "${YELLOW}⚙️  Setting up environment...${NC}"
    
    # Create necessary directories
    mkdir -p nginx/ssl
    mkdir -p data/mongodb
    mkdir -p logs
    
    # Generate SSL certificates for production (self-signed for demo)
    if [ ! -f "nginx/ssl/cert.pem" ]; then
        echo -e "${BLUE}🔐 Generating SSL certificates...${NC}"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout nginx/ssl/key.pem \
            -out nginx/ssl/cert.pem \
            -subj "/C=US/ST=CA/L=SF/O=ShadowAI/CN=localhost" 2>/dev/null || echo "OpenSSL not available, skipping SSL setup"
    fi
    
    # Set proper permissions
    chmod +x scripts/*.sh 2>/dev/null || true
    
    echo -e "${GREEN}✅ Environment setup complete${NC}"
    echo ""
}

# Check if services are already running
check_existing_services() {
    echo -e "${YELLOW}🔍 Checking for existing services...${NC}"
    
    if docker-compose ps | grep -q "Up"; then
        echo -e "${YELLOW}⚠️  Some services are already running${NC}"
        echo -e "${BLUE}Would you like to restart all services? (y/n)${NC}"
        read -r restart_choice
        if [[ $restart_choice =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}🔄 Stopping existing services...${NC}"
            docker-compose down
        fi
    fi
    echo ""
}

# Start services
start_services() {
    echo -e "${YELLOW}🚀 Starting Shadow AI Hunter services...${NC}"
    echo ""
    
    # Pull latest images
    echo -e "${BLUE}📥 Pulling Docker images...${NC}"
    docker-compose pull
    
    # Build and start services
    echo -e "${BLUE}🏗️  Building and starting services...${NC}"
    docker-compose up -d --build
    
    echo ""
    echo -e "${GREEN}✅ All services started successfully!${NC}"
    echo ""
}

# Wait for services to be healthy
wait_for_services() {
    echo -e "${YELLOW}⏳ Waiting for services to be healthy...${NC}"
    
    # Wait for MongoDB
    echo -n "   MongoDB: "
    for i in {1..30}; do
        if docker-compose exec -T mongodb mongosh --eval "db.adminCommand('ping')" &>/dev/null; then
            echo -e "${GREEN}✅ Ready${NC}"
            break
        fi
        echo -n "."
        sleep 2
    done
    
    # Wait for Backend
    echo -n "   Backend API: "
    for i in {1..30}; do
        if curl -s http://localhost:8001/api/health &>/dev/null; then
            echo -e "${GREEN}✅ Ready${NC}"
            break
        fi
        echo -n "."
        sleep 2
    done
    
    # Wait for Frontend
    echo -n "   Frontend: "
    for i in {1..30}; do
        if curl -s http://localhost:3000 &>/dev/null; then
            echo -e "${GREEN}✅ Ready${NC}"
            break
        fi
        echo -n "."
        sleep 2
    done
    
    echo ""
}

# Populate demo data
setup_demo_data() {
    echo -e "${YELLOW}📊 Setting up demo data...${NC}"
    
    # Wait a moment for API to be fully ready
    sleep 5
    
    # Populate demo data
    if curl -s -X GET "http://localhost:8001/api/demo/populate" &>/dev/null; then
        echo -e "${GREEN}✅ Demo data loaded successfully${NC}"
    else
        echo -e "${YELLOW}⚠️  Demo data setup failed, but you can load it manually from the dashboard${NC}"
    fi
    echo ""
}

# Display final information
show_completion_info() {
    echo -e "${GREEN}🎉 Shadow AI Hunter is now running!${NC}"
    echo ""
    echo -e "${BLUE}📱 Access Points:${NC}"
    echo -e "   🌐 Main Dashboard:    ${PURPLE}http://localhost${NC}"
    echo -e "   🖥️  Direct Frontend:   ${PURPLE}http://localhost:3000${NC}"
    echo -e "   🔧 Backend API:       ${PURPLE}http://localhost:8001${NC}"
    echo -e "   📚 API Documentation: ${PURPLE}http://localhost:8001/docs${NC}"
    echo ""
    
    echo -e "${BLUE}🎮 Demo Features:${NC}"
    echo -e "   • Click '${GREEN}Load Demo Data${NC}' to populate with sample security data"
    echo -e "   • Use '${GREEN}Start Network Scan${NC}' to see the scanning functionality"
    echo -e "   • Explore the dashboard to see AI risk detection in action"
    echo ""
    
    echo -e "${BLUE}⚙️  Management Commands:${NC}"
    echo -e "   📊 View service status: ${YELLOW}docker-compose ps${NC}"
    echo -e "   📋 View logs:           ${YELLOW}docker-compose logs -f${NC}"
    echo -e "   🛑 Stop services:       ${YELLOW}docker-compose down${NC}"
    echo -e "   🔄 Restart services:    ${YELLOW}docker-compose restart${NC}"
    echo ""
    
    echo -e "${BLUE}🔐 Default Credentials (Demo Mode):${NC}"
    echo -e "   Username: ${GREEN}admin${NC}"
    echo -e "   Password: ${GREEN}shadowai123${NC}"
    echo ""
    
    echo -e "${PURPLE}📞 Support & Documentation:${NC}"
    echo -e "   📖 Documentation: https://docs.shadowai.com"
    echo -e "   💬 Community: https://community.shadowai.com"
    echo -e "   🐛 Issues: https://github.com/your-org/shadow-ai-hunter/issues"
    echo ""
    
    echo -e "${YELLOW}⚠️  Production Deployment Notes:${NC}"
    echo -e "   • Change default credentials and API keys"
    echo -e "   • Configure SSL certificates for HTTPS"
    echo -e "   • Set up proper firewall rules"
    echo -e "   • Configure backup and monitoring"
    echo -e "   • Review network scanning permissions"
    echo ""
    
    echo -e "${GREEN}Happy Hunting! 🎯${NC}"
}

# Error handling
cleanup_on_error() {
    echo -e "${RED}❌ An error occurred during startup${NC}"
    echo -e "${YELLOW}🧹 Cleaning up...${NC}"
    docker-compose down 2>/dev/null || true
    exit 1
}

# Main execution
main() {
    # Set up error handling
    trap cleanup_on_error ERR
    
    # Run all setup steps
    check_permissions
    check_requirements
    setup_environment
    check_existing_services
    start_services
    wait_for_services
    setup_demo_data
    show_completion_info
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi