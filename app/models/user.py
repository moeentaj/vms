from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.core.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    
    # Profile information
    first_name = Column(String(50), nullable=True)
    last_name = Column(String(50), nullable=True)
    department = Column(String(100), nullable=True)
    phone = Column(String(20), nullable=True)
    avatar_url = Column(String(255), nullable=True)
    
    # Role and permissions
    role = Column(String(20), default="analyst")  # admin, manager, analyst, viewer
    permissions = Column(Text, nullable=True)  # JSON string for granular permissions
    
    # Status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    last_login = Column(DateTime, nullable=True)
    
    # Relationships - Use string references to avoid circular imports
    assigned_vulnerabilities = relationship(
        "VulnerabilityAssignment", 
        foreign_keys="VulnerabilityAssignment.assignee_id",
        back_populates="assignee"
    )
    created_assignments = relationship(
        "VulnerabilityAssignment", 
        foreign_keys="VulnerabilityAssignment.assigned_by_id",
        back_populates="assigned_by"
    )