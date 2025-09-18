#!/usr/bin/env python3
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.database import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash

def create_admin_user():
    db = SessionLocal()
    
    try:
        # Check if admin exists
        existing = db.query(User).filter(User.username == 'admin').first()
        if existing:
            print("Admin user already exists!")
            return
        
        # Create users
        users = [
            {'username': 'admin', 'email': 'admin@example.com', 'password': 'admin123', 'role': 'admin', 'first_name': 'System', 'last_name': 'Administrator'},
            {'username': 'manager', 'email': 'manager@example.com', 'password': 'manager123', 'role': 'manager', 'first_name': 'Security', 'last_name': 'Manager'},
            {'username': 'analyst', 'email': 'analyst@example.com', 'password': 'analyst123', 'role': 'analyst', 'first_name': 'Security', 'last_name': 'Analyst'},
            {'username': 'viewer', 'email': 'viewer@example.com', 'password': 'viewer123', 'role': 'viewer', 'first_name': 'Security', 'last_name': 'Viewer'}
        ]
        
        for user_data in users:
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                hashed_password=get_password_hash(user_data['password']),
                first_name=user_data['first_name'],
                last_name=user_data['last_name'],
                role=user_data['role'],
                is_active=True,
                is_verified=True
            )
            db.add(user)
        
        db.commit()
        print("✅ Users created successfully!")
        print("Login accounts:")
        for user_data in users:
            print(f"  {user_data['role'].title()}: {user_data['username']} / {user_data['password']}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_admin_user()
