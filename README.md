# Vulnerability Management System

AI-powered vulnerability management system with cost-optimized local AI processing.

## Quick Start

1. Clone/download this project
2. Run setup: `chmod +x start.sh && ./start.sh`
3. Access: http://localhost:8000/docs
4. Login: admin / admin123

## Features

- 🔍 Automated CVE Collection from NIST NVD
- 🤖 Local AI Analysis using Ollama (Llama 3.1)
- 👥 User Management with RBAC
- 📋 Vulnerability Assignments
- 🏢 Asset Management
- 📊 Dashboard & Analytics
- 💰 Cost-Optimized (~$44/month for production)

## Development Commands

```bash
make help          # Show all commands
make dev           # Start development
make logs          # View logs
make clean         # Clean up
make backup        # Backup database