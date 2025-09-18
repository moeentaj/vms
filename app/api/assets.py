"""
Enhanced Assets API with CPE Integration
app/api/assets.py
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import logging
import json

from app.core.database import get_db
from app.models.asset import Asset
from app.api.auth import get_current_user
from app.models.user import User
from app.services.nist_cpe_engine import CPEDatabaseManager

logger = logging.getLogger(__name__)

router = APIRouter()

class ServiceInfo(BaseModel):
    """Service information with CPE reference"""
    name: str
    vendor: Optional[str] = None
    version: Optional[str] = None
    cpe_name: Optional[str] = None
    cpe_name_id: Optional[str] = None
    ports: Optional[List[str]] = None
    detection_method: str = "manual"

class AssetResponse(BaseModel):
    """Enhanced asset response with service information"""
    id: int
    name: str
    asset_type: str
    ip_address: Optional[str]
    hostname: Optional[str]
    
    # Primary service
    primary_service: Optional[str]
    service_vendor: Optional[str]
    service_version: Optional[str]
    
    # Additional services
    additional_services: Optional[List[Dict]] = None
    
    # Asset details
    vendor: Optional[str]
    model: Optional[str]
    operating_system: Optional[str]
    os_version: Optional[str]
    
    # Environment
    environment: str
    criticality: str
    location: Optional[str]
    owner_team: Optional[str]
    
    # Status
    status: str
    is_monitored: bool
    
    # Metadata
    tags: Optional[List[str]] = None
    data_source: str
    
    class Config:
        from_attributes = True

class AssetCreateRequest(BaseModel):
    """Enhanced asset creation with CPE service lookup"""
    name: str
    asset_type: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    
    # Primary service (can be selected via CPE lookup)
    primary_service: Optional[str] = None
    service_vendor: Optional[str] = None
    service_version: Optional[str] = None
    cpe_name_id: Optional[str] = None  # Selected from CPE lookup
    cpe_name: Optional[str] = None
    
    # Additional services
    additional_services: Optional[List[ServiceInfo]] = None
    
    # Asset details
    vendor: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    
    # Operating System
    operating_system: Optional[str] = None
    os_version: Optional[str] = None
    os_cpe_name: Optional[str] = None
    
    # Environment and ownership
    environment: str = "production"
    criticality: str = "medium"
    location: Optional[str] = None
    owner_team: Optional[str] = None
    contact_email: Optional[str] = None
    business_unit: Optional[str] = None
    
    # Network information
    open_ports: Optional[List[str]] = None
    network_segment: Optional[str] = None
    
    # Status and monitoring
    status: str = "active"
    is_monitored: bool = True
    monitoring_agent: Optional[str] = None
    
    # Metadata
    tags: Optional[List[str]] = None
    notes: Optional[str] = None

class CPELookupRequest(BaseModel):
    """Request for CPE service lookup"""
    query: str
    limit: int = 20

class CPEServiceSuggestion(BaseModel):
    """CPE service suggestion for asset creation"""
    cpe_name_id: str
    cpe_name: str
    vendor: str
    product: str
    version: str
    title: Optional[str] = None
    description: Optional[str] = None
    
    class Config:
        from_attributes = True

@router.get("/", response_model=List[AssetResponse])
async def get_assets(
    skip: int = 0,
    limit: int = 100,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    asset_type: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get assets with enhanced filtering"""
    query = db.query(Asset)
    
    # Apply filters
    if environment:
        query = query.filter(Asset.environment == environment)
    if criticality:
        query = query.filter(Asset.criticality == criticality)
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            Asset.name.ilike(search_filter) |
            Asset.primary_service.ilike(search_filter) |
            Asset.hostname.ilike(search_filter) |
            Asset.ip_address.ilike(search_filter)
        )
    
    assets = query.offset(skip).limit(limit).all()
    
    # Convert to response format
    response_assets = []
    for asset in assets:
        asset_dict = {
            'id': asset.id,
            'name': asset.name,
            'asset_type': asset.asset_type,
            'ip_address': asset.ip_address,
            'hostname': asset.hostname,
            'primary_service': asset.primary_service,
            'service_vendor': asset.service_vendor,
            'service_version': asset.service_version,
            'additional_services': asset.additional_services,
            'vendor': asset.vendor,
            'model': asset.model,
            'operating_system': asset.operating_system,
            'os_version': asset.os_version,
            'environment': asset.environment,
            'criticality': asset.criticality,
            'location': asset.location,
            'owner_team': asset.owner_team,
            'status': asset.status,
            'is_monitored': asset.is_monitored,
            'tags': asset.get_tags_list(),
            'data_source': asset.data_source
        }
        response_assets.append(AssetResponse(**asset_dict))
    
    return response_assets

@router.post("/", response_model=AssetResponse)
async def create_asset(
    asset: AssetCreateRequest, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new asset with CPE service integration"""
    try:
        # Create base asset data
        asset_data = {
            'name': asset.name,
            'asset_type': asset.asset_type,
            'ip_address': asset.ip_address,
            'hostname': asset.hostname,
            'mac_address': asset.mac_address,
            'vendor': asset.vendor,
            'model': asset.model,
            'serial_number': asset.serial_number,
            'operating_system': asset.operating_system,
            'os_version': asset.os_version,
            'os_cpe_name': asset.os_cpe_name,
            'environment': asset.environment,
            'criticality': asset.criticality,
            'location': asset.location,
            'owner_team': asset.owner_team,
            'contact_email': asset.contact_email,
            'business_unit': asset.business_unit,
            'network_segment': asset.network_segment,
            'status': asset.status,
            'is_monitored': asset.is_monitored,
            'monitoring_agent': asset.monitoring_agent,
            'notes': asset.notes,
            'created_by': current_user.username,
            'data_source': 'cpe' if asset.cpe_name_id else 'manual'
        }
        
        # Handle primary service with CPE reference
        if asset.cpe_name_id:
            # Get CPE data for validation and enrichment
            cpe_manager = CPEDatabaseManager(db)
            if cpe_manager.load_cached_cpe_data():
                cpe_product = cpe_manager.get_product_by_id(asset.cpe_name_id)
                if cpe_product:
                    asset_data.update({
                        'primary_service': asset.primary_service or cpe_product.product,
                        'service_vendor': asset.service_vendor or cpe_product.vendor,
                        'service_version': asset.service_version or cpe_product.version,
                        'cpe_name': cpe_product.cpe_name,
                        'cpe_name_id': cpe_product.cpe_name_id,
                        'cpe_product': cpe_product.product,
                        'detection_confidence': 0.9
                    })
        else:
            # Manual service entry
            asset_data.update({
                'primary_service': asset.primary_service,
                'service_vendor': asset.service_vendor,
                'service_version': asset.service_version
            })
        
        # Handle additional services
        if asset.additional_services:
            additional_services_data = []
            for service in asset.additional_services:
                service_data = {
                    'name': service.name,
                    'vendor': service.vendor,
                    'version': service.version,
                    'ports': service.ports or [],
                    'detection_method': service.detection_method
                }
                
                # Add CPE reference if provided
                if service.cpe_name_id:
                    service_data.update({
                        'cpe_name': service.cpe_name,
                        'cpe_name_id': service.cpe_name_id
                    })
                
                additional_services_data.append(service_data)
            
            asset_data['additional_services'] = additional_services_data
        
        # Handle structured fields
        if asset.open_ports:
            asset_data['open_ports'] = asset.open_ports
        
        if asset.tags:
            asset_data['tags'] = asset.tags
        
        # Create asset
        db_asset = Asset(**asset_data)
        db.add(db_asset)
        db.commit()
        db.refresh(db_asset)
        
        # Convert to response format
        response_data = {
            'id': db_asset.id,
            'name': db_asset.name,
            'asset_type': db_asset.asset_type,
            'ip_address': db_asset.ip_address,
            'hostname': db_asset.hostname,
            'primary_service': db_asset.primary_service,
            'service_vendor': db_asset.service_vendor,
            'service_version': db_asset.service_version,
            'additional_services': db_asset.additional_services,
            'vendor': db_asset.vendor,
            'model': db_asset.model,
            'operating_system': db_asset.operating_system,
            'os_version': db_asset.os_version,
            'environment': db_asset.environment,
            'criticality': db_asset.criticality,
            'location': db_asset.location,
            'owner_team': db_asset.owner_team,
            'status': db_asset.status,
            'is_monitored': db_asset.is_monitored,
            'tags': db_asset.get_tags_list(),
            'data_source': db_asset.data_source
        }
        
        return AssetResponse(**response_data)
        
    except Exception as e:
        logger.error(f"Error creating asset: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create asset: {str(e)}")

@router.post("/cpe-lookup", response_model=List[CPEServiceSuggestion])
async def lookup_cpe_services(
    lookup_request: CPELookupRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Search CPE database for service suggestions during asset creation"""
    try:
        cpe_manager = CPEDatabaseManager(db)
        if not cpe_manager.load_cached_cpe_data():
            raise HTTPException(
                status_code=404, 
                detail="CPE data not available. Please run CPE data ingestion first."
            )
        
        # Search CPE products
        results, total_count = cpe_manager.search_products(
            query=lookup_request.query,
            limit=lookup_request.limit,
            offset=0
        )
        
        # Convert to service suggestions
        suggestions = []
        for cpe_product in results:
            # Get English title
            title = None
            for t in cpe_product.titles:
                if t.get('lang') == 'en':
                    title = t.get('title')
                    break
            
            suggestions.append(CPEServiceSuggestion(
                cpe_name_id=cpe_product.cpe_name_id,
                cpe_name=cpe_product.cpe_name,
                vendor=cpe_product.vendor,
                product=cpe_product.product,
                version=cpe_product.version,
                title=title,
                description=title or f"{cpe_product.product} by {cpe_product.vendor}"
            ))
        
        return suggestions
        
    except Exception as e:
        logger.error(f"Error in CPE lookup: {e}")
        raise HTTPException(status_code=500, detail=f"CPE lookup failed: {str(e)}")

@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: int, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get specific asset with full service information"""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    response_data = {
        'id': asset.id,
        'name': asset.name,
        'asset_type': asset.asset_type,
        'ip_address': asset.ip_address,
        'hostname': asset.hostname,
        'primary_service': asset.primary_service,
        'service_vendor': asset.service_vendor,
        'service_version': asset.service_version,
        'additional_services': asset.additional_services,
        'vendor': asset.vendor,
        'model': asset.model,
        'operating_system': asset.operating_system,
        'os_version': asset.os_version,
        'environment': asset.environment,
        'criticality': asset.criticality,
        'location': asset.location,
        'owner_team': asset.owner_team,
        'status': asset.status,
        'is_monitored': asset.is_monitored,
        'tags': asset.get_tags_list(),
        'data_source': asset.data_source
    }
    
    return AssetResponse(**response_data)

@router.put("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: int,
    asset_update: AssetCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update asset with service information"""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Update fields (similar logic to create_asset)
    update_data = asset_update.dict(exclude_unset=True)
    update_data['last_modified_by'] = current_user.username
    
    for field, value in update_data.items():
        if hasattr(asset, field):
            setattr(asset, field, value)
    
    db.commit()
    db.refresh(asset)
    
    # Return updated asset
    response_data = {
        'id': asset.id,
        'name': asset.name,
        'asset_type': asset.asset_type,
        'ip_address': asset.ip_address,
        'hostname': asset.hostname,
        'primary_service': asset.primary_service,
        'service_vendor': asset.service_vendor,
        'service_version': asset.service_version,
        'additional_services': asset.additional_services,
        'vendor': asset.vendor,
        'model': asset.model,
        'operating_system': asset.operating_system,
        'os_version': asset.os_version,
        'environment': asset.environment,
        'criticality': asset.criticality,
        'location': asset.location,
        'owner_team': asset.owner_team,
        'status': asset.status,
        'is_monitored': asset.is_monitored,
        'tags': asset.get_tags_list(),
        'data_source': asset.data_source
    }
    
    return AssetResponse(**response_data)

@router.delete("/{asset_id}")
async def delete_asset(
    asset_id: int, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete asset"""
    if current_user.role not in ["admin", "manager"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    db.delete(asset)
    db.commit()
    return {"message": "Asset deleted successfully"}

@router.get("/{asset_id}/cpe-references")
async def get_asset_cpe_references(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all CPE references for an asset"""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    return {
        "asset_id": asset_id,
        "asset_name": asset.name,
        "cpe_references": asset.get_all_cpe_references()
    }