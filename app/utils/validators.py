# app/utils/validators.py
"""
Request Validation Schemas
Comprehensive validation for all API endpoints
"""

from pydantic import BaseModel, validator, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, date
from enum import Enum

# Enums for validation
class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

class Priority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AssetType(str, Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    DATABASE = "database"
    APPLICATION = "application"
    CONTAINER = "container"
    IOT_DEVICE = "iot_device"
    OTHER = "other"

class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"

class Criticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class AssignmentStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"

# CVE Validation Schemas
class CVEQueryParams(BaseModel):
    page: Optional[int] = Field(default=1, ge=1, description="Page number")
    limit: Optional[int] = Field(default=20, ge=1, le=100, description="Items per page")
    severity: Optional[SeverityLevel] = Field(default=None, description="Filter by severity")
    search: Optional[str] = Field(default=None, max_length=500, description="Search term")
    processed: Optional[bool] = Field(default=None, description="Filter by processing status")
    published_after: Optional[date] = Field(default=None, description="Filter by publish date")
    has_analysis: Optional[bool] = Field(default=None, description="Filter by AI analysis status")
    
    @validator('search')
    def validate_search(cls, v):
        if v is not None and len(v.strip()) < 2:
            raise ValueError('Search term must be at least 2 characters')
        return v.strip() if v else None

class CVECollectionRequest(BaseModel):
    days_back: int = Field(default=7, ge=1, le=365, description="Days to look back")
    use_files: bool = Field(default=True, description="Use file-based collection")
    force_refresh: bool = Field(default=False, description="Force refresh of existing CVEs")
    
    @validator('days_back')
    def validate_days_back(cls, v):
        if v > 30:
            # Log warning for large collections
            import logging
            logging.getLogger(__name__).warning(f"Large CVE collection requested: {v} days")
        return v

# Asset Validation Schemas
class AssetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    asset_type: AssetType
    ip_address: Optional[str] = Field(default=None, regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    hostname: Optional[str] = Field(default=None, max_length=255)
    environment: Environment = Field(default=Environment.PRODUCTION)
    criticality: Criticality = Field(default=Criticality.MEDIUM)
    location: Optional[str] = Field(default=None, max_length=255)
    primary_service: Optional[str] = Field(default=None, max_length=255)
    service_vendor: Optional[str] = Field(default=None, max_length=255)
    service_version: Optional[str] = Field(default=None, max_length=100)
    cpe_name_id: Optional[str] = Field(default=None, max_length=500)
    operating_system: Optional[str] = Field(default=None, max_length=255)
    os_version: Optional[str] = Field(default=None, max_length=100)
    tags: Optional[List[str]] = Field(default=None)
    metadata: Optional[Dict[str, Any]] = Field(default=None)
    
    @validator('name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Asset name cannot be empty')
        return v.strip()
    
    @validator('tags')
    def validate_tags(cls, v):
        if v is not None:
            # Remove duplicates and empty tags
            tags = [tag.strip() for tag in v if tag.strip()]
            if len(tags) > 20:
                raise ValueError('Maximum 20 tags allowed')
            return tags
        return v

class AssetUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    asset_type: Optional[AssetType] = None
    ip_address: Optional[str] = Field(default=None, regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    hostname: Optional[str] = Field(default=None, max_length=255)
    environment: Optional[Environment] = None
    criticality: Optional[Criticality] = None
    location: Optional[str] = Field(default=None, max_length=255)
    primary_service: Optional[str] = Field(default=None, max_length=255)
    service_vendor: Optional[str] = Field(default=None, max_length=255)
    service_version: Optional[str] = Field(default=None, max_length=100)
    cpe_name_id: Optional[str] = Field(default=None, max_length=500)
    operating_system: Optional[str] = Field(default=None, max_length=255)
    os_version: Optional[str] = Field(default=None, max_length=100)
    tags: Optional[List[str]] = Field(default=None)
    metadata: Optional[Dict[str, Any]] = Field(default=None)
    is_monitored: Optional[bool] = None
    
    @validator('name')
    def validate_name(cls, v):
        if v is not None and not v.strip():
            raise ValueError('Asset name cannot be empty')
        return v.strip() if v else None

class AssetQueryParams(BaseModel):
    page: Optional[int] = Field(default=1, ge=1)
    limit: Optional[int] = Field(default=20, ge=1, le=100)
    asset_type: Optional[AssetType] = None
    environment: Optional[Environment] = None
    criticality: Optional[Criticality] = None
    search: Optional[str] = Field(default=None, max_length=500)
    has_vulnerabilities: Optional[bool] = None
    is_monitored: Optional[bool] = None

# Assignment Validation Schemas
class AssignmentCreate(BaseModel):
    cve_id: str = Field(..., min_length=1, max_length=50)
    assignee_id: int = Field(..., gt=0)
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field(..., min_length=1, max_length=2000)
    priority: Priority = Field(default=Priority.MEDIUM)
    due_date: Optional[date] = None
    
    @validator('title')
    def validate_title(cls, v):
        return v.strip()
    
    @validator('description')
    def validate_description(cls, v):
        return v.strip()
    
    @validator('due_date')
    def validate_due_date(cls, v):
        if v is not None and v < date.today():
            raise ValueError('Due date cannot be in the past')
        return v

class AssignmentUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=500)
    description: Optional[str] = Field(default=None, min_length=1, max_length=2000)
    priority: Optional[Priority] = None
    status: Optional[AssignmentStatus] = None
    due_date: Optional[date] = None
    assignee_id: Optional[int] = Field(default=None, gt=0)
    resolution_notes: Optional[str] = Field(default=None, max_length=2000)
    
    @validator('due_date')
    def validate_due_date(cls, v):
        if v is not None and v < date.today():
            raise ValueError('Due date cannot be in the past')
        return v

class AssignmentQueryParams(BaseModel):
    page: Optional[int] = Field(default=1, ge=1)
    limit: Optional[int] = Field(default=20, ge=1, le=100)
    status: Optional[AssignmentStatus] = None
    priority: Optional[Priority] = None
    assignee_id: Optional[int] = Field(default=None, gt=0)
    overdue: Optional[bool] = None
    search: Optional[str] = Field(default=None, max_length=500)

# User/Auth Validation Schemas
class UserLogin(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1)

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    email: str = Field(..., regex=r'^[^@]+@[^@]+\.[^@]+$')
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(..., min_length=1, max_length=255)
    role: Optional[str] = Field(default="analyst", regex=r'^(admin|manager|analyst|viewer)$')
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

class UserUpdate(BaseModel):
    email: Optional[str] = Field(default=None, regex=r'^[^@]+@[^@]+\.[^@]+$')
    full_name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    role: Optional[str] = Field(default=None, regex=r'^(admin|manager|analyst|viewer)$')

# CPE/Correlation Validation Schemas
class CPELookupRequest(BaseModel):
    cpe_name: str = Field(..., min_length=1, max_length=500)
    include_vulnerabilities: bool = Field(default=True)
    limit: Optional[int] = Field(default=100, ge=1, le=1000)

# Bulk Operations
class BulkAssetUpdate(BaseModel):
    asset_ids: List[int] = Field(..., min_items=1, max_items=100)
    updates: AssetUpdate
    
    @validator('asset_ids')
    def validate_asset_ids(cls, v):
        if len(set(v)) != len(v):
            raise ValueError('Duplicate asset IDs not allowed')
        return v

class BulkAssignmentCreate(BaseModel):
    assignments: List[AssignmentCreate] = Field(..., min_items=1, max_items=50)
    
    @validator('assignments')
    def validate_assignments(cls, v):
        cve_ids = [a.cve_id for a in v]
        if len(set(cve_ids)) != len(cve_ids):
            raise ValueError('Duplicate CVE IDs in bulk assignment not allowed')
        return v