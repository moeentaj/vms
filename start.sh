#!/bin/bash

echo "🚀 Starting Vulnerability Management System..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
	sleep 15
    exit 1
fi

# Check if .env exists
if [ ! -f .env ]; then
    echo "📝 Creating environment file..."
    cp .env.example .env
fi

# Start services
echo "🐳 Starting services..."
docker-compose up -d --build

# Wait for services
echo "⏳ Waiting for services..."
sleep 30

# Create admin user
echo "👤 Creating admin user..."
docker-compose exec app python create_admin_user.py

echo "✅ System ready!"
echo "🌐 Access URLs:"
echo "  API: http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
echo "  Database: http://localhost:8080"
echo "  Monitoring: http://localhost:3000"
echo ""
echo "👥 Login: admin / admin123"