"""
CPE Lookup API Endpoints - Manual Service Creation with CPE Reference
app/api/cpe_lookup.py
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import logging
import time
import json

from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.services.nist_cpe_engine import (
    CPEDatabaseManager, 
    refresh_cpe_data,
    check_cpe_data_freshness
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Pydantic Models for CPE Lookup
class CPEProductSearchRequest(BaseModel):
    """Request model for CPE product search"""
    query: str
    vendor_filter: Optional[str] = None
    product_filter: Optional[str] = None
    version_filter: Optional[str] = None
    include_deprecated: bool = False
    limit: int = 50
    offset: int = 0

class CPEProductResponse(BaseModel):
    """Response model for CPE product information"""
    cpe_name: str
    cpe_name_id: str
    vendor: str
    product: str
    version: str
    title: Optional[str] = None
    description: Optional[str] = None
    last_modified: Optional[str] = None
    deprecated: bool = False
    references: List[Dict[str, str]] = []
    
    class Config:
        from_attributes = True

class CPESearchResponse(BaseModel):
    """Response model for CPE search results"""
    products: List[CPEProductResponse]
    total_count: int
    search_query: str
    filters_applied: Dict[str, Any]
    execution_time_ms: int

class CPEDataStatusResponse(BaseModel):
    """Response model for CPE data status"""
    has_data: bool
    needs_refresh: bool
    cache_age_hours: Optional[float] = None
    total_products: int = 0
    last_refresh: Optional[str] = None
    reason: str

class DataSourceStatusResponse(BaseModel):
    """Response model for data source status"""
    id: str
    name: str
    description: str
    status: str  # active, planned, error, disabled
    record_count: int
    last_sync: Optional[str] = None
    config_required: bool = False
    error_message: Optional[str] = None

class ServiceCreationWithCPERequest(BaseModel):
    """Request model for creating service with CPE reference"""
    # Service Type fields
    category_id: int
    service_name: str
    vendor: Optional[str] = None
    description: Optional[str] = None
    default_ports: Optional[str] = None
    
    # CPE Reference (optional)
    cpe_name_id: Optional[str] = None
    cpe_name: Optional[str] = None
    
    # Service Instance fields
    instance_name: str
    version: Optional[str] = None
    environment: str = "production"
    criticality: str = "medium"
    hostname: Optional[str] = None
    ip_addresses: Optional[str] = None
    ports: Optional[str] = None
    location: Optional[str] = None
    owner_team: Optional[str] = None
    contact_email: Optional[str] = None
    status: str = "active"
    is_monitored: bool = True
    tags: Optional[str] = None
    notes: Optional[str] = None

# CPE Data Management Endpoints
@router.post("/ingest")
async def trigger_cpe_data_refresh(
    background_tasks: BackgroundTasks,
    force_refresh: bool = Query(False, description="Force refresh even if cache is fresh"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Trigger CPE data refresh for lookup functionality"""
    if current_user.role not in ["admin", "manager"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Check if refresh is needed
    if not force_refresh:
        status = check_cpe_data_freshness(db)
        if status['has_data'] and not status['needs_refresh']:
            return {
                "success": True,
                "message": "CPE data is fresh, no refresh needed",
                "cache_used": True,
                "status": status
            }
    
    background_tasks.add_task(refresh_cpe_data_task, db)
    return {
        "success": True,
        "message": "CPE data refresh started in background",
        "cache_used": False
    }

@router.get("/status", response_model=CPEDataStatusResponse)
async def get_cpe_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get CPE data status and freshness"""
    try:
        status = check_cpe_data_freshness(db)
        
        # Get additional stats if data exists
        total_products = 0
        last_refresh = None
        
        if status['has_data']:
            cpe_manager = CPEDatabaseManager(db)
            if cpe_manager.load_cached_cpe_data():
                total_products = len(cpe_manager.cpe_products)
                if cpe_manager.cache_file.exists():
                    try:
                        with open(cpe_manager.cache_file, 'r') as f:
                            cache_data = json.load(f)
                            last_refresh = cache_data.get('download_date')
                    except:
                        pass
        
        return CPEDataStatusResponse(
            has_data=status['has_data'],
            needs_refresh=status['needs_refresh'],
            cache_age_hours=status.get('cache_age_hours'),
            total_products=total_products,
            last_refresh=last_refresh,
            reason=status['reason']
        )
        
    except Exception as e:
        logger.error(f"Error getting CPE status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")

# CPE Product Search Endpoints
@router.post("/search", response_model=CPESearchResponse)
async def search_cpe_products(
    search_request: CPEProductSearchRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Search CPE products for manual lookup"""
    start_time = time.time()
    
    try:
        cpe_manager = CPEDatabaseManager(db)
        if not cpe_manager.load_cached_cpe_data():
            raise HTTPException(
                status_code=404, 
                detail="CPE data not available. Please run data ingestion first."
            )
        
        # Perform search
        results, total_count = cpe_manager.search_products(
            query=search_request.query,
            vendor_filter=search_request.vendor_filter,
            product_filter=search_request.product_filter,
            version_filter=search_request.version_filter,
            include_deprecated=search_request.include_deprecated,
            limit=search_request.limit,
            offset=search_request.offset
        )
        
        # Convert to response format
        products = []
        for cpe_product in results:
            # Get English title
            title = None
            for t in cpe_product.titles:
                if t.get('lang') == 'en':
                    title = t.get('title')
                    break
            
            products.append(CPEProductResponse(
                cpe_name=cpe_product.cpe_name,
                cpe_name_id=cpe_product.cpe_name_id,
                vendor=cpe_product.vendor,
                product=cpe_product.product,
                version=cpe_product.version,
                title=title,
                description=title,  # Use title as description for now
                last_modified=cpe_product.last_modified.isoformat() if cpe_product.last_modified else None,
                deprecated=cpe_product.deprecated,
                references=cpe_product.references
            ))
        
        execution_time = int((time.time() - start_time) * 1000)
        
        return CPESearchResponse(
            products=products,
            total_count=total_count,
            search_query=search_request.query,
            filters_applied={
                "vendor_filter": search_request.vendor_filter,
                "product_filter": search_request.product_filter,
                "version_filter": search_request.version_filter,
                "include_deprecated": search_request.include_deprecated
            },
            execution_time_ms=execution_time
        )
        
    except Exception as e:
        logger.error(f"Error searching CPE products: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

@router.get("/product/{cpe_name_id}", response_model=CPEProductResponse)
async def get_cpe_product(
    cpe_name_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific CPE product"""
    try:
        cpe_manager = CPEDatabaseManager(db)
        if not cpe_manager.load_cached_cpe_data():
            raise HTTPException(
                status_code=404, 
                detail="CPE data not available. Please run data ingestion first."
            )
        
        # Find product by ID
        product = cpe_manager.get_product_by_id(cpe_name_id)
        if not product:
            raise HTTPException(status_code=404, detail="CPE product not found")
        
        # Get English title
        title = None
        for t in product.titles:
            if t.get('lang') == 'en':
                title = t.get('title')
                break
        
        return CPEProductResponse(
            cpe_name=product.cpe_name,
            cpe_name_id=product.cpe_name_id,
            vendor=product.vendor,
            product=product.product,
            version=product.version,
            title=title,
            description=title,
            last_modified=product.last_modified.isoformat() if product.last_modified else None,
            deprecated=product.deprecated,
            references=product.references
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting CPE product: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get product: {str(e)}")

@router.get("/vendors")
async def get_vendors(
    query: Optional[str] = Query(None, description="Filter vendors by name"),
    limit: int = Query(50, description="Maximum number of vendors to return"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of vendors for filtering"""
    try:
        cpe_manager = CPEDatabaseManager(db)
        if not cpe_manager.load_cached_cpe_data():
            raise HTTPException(
                status_code=404, 
                detail="CPE data not available. Please run data ingestion first."
            )
        
        vendors = cpe_manager.get_vendors(query=query, limit=limit)
        return {"vendors": vendors}
        
    except Exception as e:
        logger.error(f"Error getting vendors: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get vendors: {str(e)}")

# Data Source Management
@router.get("/data-sources", response_model=List[DataSourceStatusResponse])
async def get_data_sources(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get status of all data sources"""
    try:
        # Get CPE status
        cpe_status = check_cpe_data_freshness(db)
        cpe_manager = CPEDatabaseManager(db)
        
        total_products = 0
        last_sync = None
        
        if cpe_status['has_data'] and cpe_manager.load_cached_cpe_data():
            total_products = len(cpe_manager.cpe_products)
            if cpe_manager.cache_file.exists():
                try:
                    with open(cpe_manager.cache_file, 'r') as f:
                        cache_data = json.load(f)
                        last_sync = cache_data.get('download_date')
                except:
                    pass
        
        data_sources = [
            DataSourceStatusResponse(
                id="cpe",
                name="NIST CPE Database",
                description="Official NIST Common Platform Enumeration database for product identification",
                status="active" if cpe_status['has_data'] else "error",
                record_count=total_products,
                last_sync=last_sync,
                config_required=False,
                error_message=None if cpe_status['has_data'] else "No data available - run ingestion"
            ),
            DataSourceStatusResponse(
                id="nmap",
                name="Nmap Discovery",
                description="Network discovery and service identification from Nmap scans",
                status="planned",
                record_count=0,
                last_sync=None,
                config_required=True,
                error_message=None
            ),
            DataSourceStatusResponse(
                id="nessus",
                name="Nessus Vulnerability Scanner",
                description="Service detection and vulnerability assessment from Nessus scans",
                status="planned",
                record_count=0,
                last_sync=None,
                config_required=True,
                error_message=None
            ),
            DataSourceStatusResponse(
                id="custom_agent",
                name="Custom Discovery Agent",
                description="Custom service discovery agents and manual imports",
                status="planned",
                record_count=0,
                last_sync=None,
                config_required=True,
                error_message=None
            )
        ]
        
        return data_sources
        
    except Exception as e:
        logger.error(f"Error getting data sources: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get data sources: {str(e)}")

@router.delete("/cache")
async def clear_cpe_cache(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Clear CPE cache to force fresh download on next ingestion"""
    if current_user.role not in ["admin", "manager"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    try:
        cpe_manager = CPEDatabaseManager(db)
        if cpe_manager.cache_file.exists():
            cpe_manager.cache_file.unlink()
            return {"success": True, "message": "CPE cache cleared"}
        else:
            return {"success": True, "message": "No cache to clear"}
            
    except Exception as e:
        logger.error(f"Error clearing CPE cache: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear cache: {str(e)}")

# Utility functions
def parse_version_components(version_string: str) -> Dict[str, Any]:
    """Parse version string into components"""
    import re
    
    if not version_string:
        return {}
    
    # Try common version patterns
    patterns = [
        r'^(\d+)\.(\d+)\.(\d+)\.(\d+)$',  # 1.2.3.4
        r'^(\d+)\.(\d+)\.(\d+)-(.+)$',    # 1.2.3-beta1
        r'^(\d+)\.(\d+)\.(\d+)$',         # 1.2.3
        r'^(\d+)\.(\d+)$',                # 1.2
        r'^(\d+)$',                       # 1
    ]
    
    for pattern in patterns:
        match = re.match(pattern, version_string.strip())
        if match:
            groups = match.groups()
            result = {}
            
            if len(groups) >= 1:
                result['version_major'] = int(groups[0])
            if len(groups) >= 2:
                result['version_minor'] = int(groups[1])
            if len(groups) >= 3:
                result['version_patch'] = int(groups[2])
            if len(groups) >= 4:
                # Fourth group could be build string
                try:
                    result['version_patch'] = int(groups[3])
                except ValueError:
                    result['version_build'] = groups[3]
            
            result['version_full'] = version_string
            return result
    
    return {'version_full': version_string}

# Background task function
async def refresh_cpe_data_task(db: Session):
    """Background task for CPE data refresh"""
    try:
        stats = await refresh_cpe_data(db)
        logger.info(f"CPE data refresh completed: {stats}")
        return stats
    except Exception as e:
        logger.error(f"CPE data refresh task failed: {e}")
        raise