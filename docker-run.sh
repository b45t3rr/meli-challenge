#!/bin/bash

# GenIA - Docker Runner Script
# This script helps you run the GenIA vulnerability scanner in Docker

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}GenIA - Vulnerability Validation System${NC}"
echo -e "${BLUE}======================================${NC}"

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Warning: .env file not found. Creating from .env.example...${NC}"
    cp .env.example .env
    echo -e "${RED}Please edit .env file with your API keys before running the application.${NC}"
    exit 1
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running. Please start Docker and try again.${NC}"
    exit 1
fi

# Create reports directory if it doesn't exist
mkdir -p reports

echo -e "${GREEN}Starting GenIA services...${NC}"

# Start services
docker-compose up -d

echo -e "${GREEN}Services started successfully!${NC}"
echo -e "${BLUE}MongoDB is available at: localhost:27017${NC}"
echo -e "${BLUE}Application container: genia_vulnerability_scanner${NC}"
echo ""
echo -e "${YELLOW}To run vulnerability analysis:${NC}"
echo "docker-compose exec genia-app python app.py --pdf /app/testing-assets/report.pdf --source /app/testing-assets/vuln-app-main"
echo ""
echo -e "${YELLOW}To access the application container:${NC}"
echo "docker-compose exec genia-app bash"
echo ""
echo -e "${YELLOW}To stop services:${NC}"
echo "docker-compose down"
echo ""
echo -e "${YELLOW}To view logs:${NC}"
echo "docker-compose logs -f genia-app"