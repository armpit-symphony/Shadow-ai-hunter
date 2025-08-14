#!/bin/bash

# Shadow AI Hunter - Stop Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛑 Stopping Shadow AI Hunter services...${NC}"

# Stop all services
echo -e "${YELLOW}📱 Stopping containers...${NC}"
docker-compose down

# Optional: Remove volumes (uncomment if you want to clear all data)
# echo -e "${YELLOW}🗑️  Removing data volumes...${NC}"
# docker-compose down -v

# Optional: Remove images (uncomment if you want to remove built images)
# echo -e "${YELLOW}🖼️  Removing built images...${NC}"
# docker-compose down --rmi all

echo -e "${GREEN}✅ All services stopped successfully${NC}"
echo ""
echo -e "${BLUE}💡 To restart: ./start.sh${NC}"