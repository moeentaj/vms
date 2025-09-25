"""
Enhanced CPE Lookup API - app/api/enhanced_cpe_lookup.py
Complete API replacement with enhanced search capabilities
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import logging
import time

from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.services.enhanced_cpe_engine import EnhancedCPEDatabaseManager

logger = logging.getLogger(__name__)

router = APIRouter()

# Enhanced Pydantic Models
class EnhancedCPESearchRequest(BaseModel):
    """Enhanced search request with metadata support"""
    query: str = Field(..., description="Search query")
    vendor_filter: Optional[str] = Field(None, description="Filter by vendor")
    product_filter: Optional[str] = Field(None, description="Filter by product")
    version_filter: Optional[str] = Field(None, description="Filter by version")
    category_filter: Optional[str] = Field(None, description="Filter by category")
    include_deprecated: bool = Field(False, description="Include deprecated products")
    limit: int = Field(50, description="Maximum results", ge=1, le=100)
    offset: int = Field(0, description="Result offset", ge=0)

class EnhancedCPEProductResponse(BaseModel):
    """Enhanced CPE product response with rich metadata"""
    cpe_name: str
    cpe_name_id: str
    vendor: str
    product: str
    version: str
    
    # Enhanced metadata
    titles: List[Dict[str, str]] = Field(default_factory=list, description="Multi-language titles")
    references: List[Dict[str, str]] = Field(default_factory=list, description="External references")
    categories: List[str] = Field(default_factory=list, description="Product categories")
    keywords: List[str] = Field(default_factory=list, description="Search keywords")
    alternative_names: List[str] = Field(default_factory=list, description="Alternative product names")
    vendor_aliases: List[str] = Field(default_factory=list, description="Vendor aliases")
    
    # Lifecycle information
    deprecated: bool = False
    deprecation_date: Optional[str] = None
    deprecated_by: List[str] = Field(default_factory=list, description="Replacement CPEs")
    
    # Metadata
    last_modified: Optional[str] = None
    created: Optional[str] = None
    popularity_score: float = Field(0.0, description="Popularity/relevance score")
    search_score: Optional[float] = Field(None, description="Search match score")

class EnhancedCPESearchResponse(BaseModel):
    """Enhanced search response with metadata"""
    products: List[EnhancedCPEProductResponse]
    total_count: int
    search_query: str
    normalized_query: str
    filters_applied: Dict[str, Any]
    categories_found: List[str] = Field(default_factory=list)
    execution_time_ms: int
    search_suggestions: List[str] = Field(default_factory=list)

class CPEStatusResponse(BaseModel):
    """CPE database status"""
    has_data: bool
    total_products: int
    last_updated: Optional[str]
    cache_file_exists: bool
    categories_available: List[str] = Field(default_factory=list)
    vendors_count: int = 0

# API Endpoints

@router.get("/status", response_model=CPEStatusResponse)
async def get_enhanced_cpe_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get enhanced CPE database status"""
    try:
        cpe_manager = EnhancedCPEDatabaseManager(db)
        
        # Try to load cached data to get status
        has_cached_data = cpe_manager.load_cached_cpe_data()
        
        status = CPEStatusResponse(
            has_data=has_cached_data,
            total_products=len(cpe_manager.cpe_products) if has_cached_data else 0,
            last_updated=None,
            cache_file_exists=cpe_manager.cache_file.exists(),
            categories_available=cpe_manager.get_categories() if has_cached_data else [],
            vendors_count=len(cpe_manager.get_vendors()) if has_cached_data else 0
        )
        
        # Get cache file timestamp if it exists
        if cpe_manager.cache_file.exists():
            import datetime
            timestamp = datetime.datetime.fromtimestamp(
                cpe_manager.cache_file.stat().st_mtime
            )
            status.last_updated = timestamp.isoformat()
        
        return status
        
    except Exception as e:
        logger.error(f"Error getting CPE status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")

@router.post("/ingest")
async def ingest_enhanced_cpe_data(
    background_tasks: BackgroundTasks,
    force_refresh: bool = Query(False, description="Force refresh of cached data"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Trigger enhanced CPE data ingestion"""
    try:
        cpe_manager = EnhancedCPEDatabaseManager(db)
        
        # Run ingestion in background
        background_tasks.add_task(
            _background_cpe_ingestion, 
            cpe_manager, 
            force_refresh
        )
        
        return {
            "message": "Enhanced CPE data ingestion started",
            "force_refresh": force_refresh,
            "estimated_time_minutes": "5-15"
        }
        
    except Exception as e:
        logger.error(f"Error starting CPE ingestion: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start ingestion: {str(e)}")

async def _background_cpe_ingestion(cpe_manager: EnhancedCPEDatabaseManager, force_refresh: bool):
    """Background task for CPE ingestion"""
    try:
        logger.info("Starting background enhanced CPE ingestion")
        stats = await cpe_manager.ingest_cpe_data(force_refresh=force_refresh)
        logger.info(f"Enhanced CPE ingestion completed: {stats}")
    except Exception as e:
        logger.error(f"Background CPE ingestion failed: {e}")

@router.post("/search", response_model=EnhancedCPESearchResponse)
async def enhanced_cpe_search(
    search_request: EnhancedCPESearchRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Enhanced CPE product search with metadata"""
    try:
        start_time = time.time()
        
        cpe_manager = EnhancedCPEDatabaseManager(db)
        if not cpe_manager.load_cached_cpe_data():
            raise HTTPException(
                status_code=404,
                detail="Enhanced CPE data not available. Please run data ingestion first."
            )
        
        # Perform enhanced search
        results, total_count = cpe_manager.enhanced_search_products(
            query=search_request.query,
            vendor_filter=search_request.vendor_filter,
            product_filter=search_request.product_filter,
            version_filter=search_request.version_filter,
            category_filter=search_request.category_filter,
            include_deprecated=search_request.include_deprecated,
            limit=search_request.limit,
            offset=search_request.offset
        )
        
        # Convert to response format
        products = []
        categories_found = set()
        
        for cpe_product in results:
            # Get search score if available
            search_score = getattr(cpe_product, '_search_score', None)
            
            product_response = EnhancedCPEProductResponse(
                cpe_name=cpe_product.cpe_name,
                cpe_name_id=cpe_product.cpe_name_id,
                vendor=cpe_product.vendor,
                product=cpe_product.product,
                version=cpe_product.version,
                titles=[{"title": t.title, "lang": t.lang} for t in cpe_product.titles],
                references=[{"href": r.href, "type": r.ref_type, "content": r.content} 
                           for r in cpe_product.references],
                categories=list(cpe_product.categories),
                keywords=list(cpe_product.keywords)[:20],  # Limit keywords
                alternative_names=list(cpe_product.alternative_names),
                vendor_aliases=list(cpe_product.vendor_aliases),
                deprecated=cpe_product.deprecated,
                deprecation_date=cpe_product.deprecation_date.isoformat() if cpe_product.deprecation_date else None,
                deprecated_by=cpe_product.deprecated_by,
                last_modified=cpe_product.last_modified.isoformat() if cpe_product.last_modified else None,
                created=cpe_product.created.isoformat() if cpe_product.created else None,
                popularity_score=cpe_product.popularity_score,
                search_score=search_score
            )
            products.append(product_response)
            categories_found.update(cpe_product.categories)
        
        # Get search suggestions
        suggestions = cpe_manager.get_search_suggestions(search_request.query, limit=5)
        
        execution_time = int((time.time() - start_time) * 1000)
        
        # Get normalized query for debugging
        normalized_query = cpe_manager._preprocess_search_query(search_request.query)
        
        return EnhancedCPESearchResponse(
            products=products,
            total_count=total_count,
            search_query=search_request.query,
            normalized_query=normalized_query,
            filters_applied={
                "vendor_filter": search_request.vendor_filter,
                "product_filter": search_request.product_filter,
                "version_filter": search_request.version_filter,
                "category_filter": search_request.category_filter,
                "include_deprecated": search_request.include_deprecated
            },
            categories_found=list(categories_found),
            execution_time_ms=execution_time,
            search_suggestions=suggestions
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in enhanced CPE search: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

@router.get("/search")
async def enhanced_cpe_search_get(
    q: str = Query(..., description="Search query"),
    vendor: Optional[str] = Query(None, description="Vendor filter"),
    product: Optional[str] = Query(None, description="Product filter"),
    version: Optional[str] = Query(None, description="Version filter"),
    category: Optional[str] = Query(None, description="Category filter"),
    include_deprecated: bool = Query(False, description="Include deprecated"),
    limit: int = Query(20, description="Result limit", ge=1, le=100),
    offset: int = Query(0, description="Result offset", ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Enhanced CPE search via GET request (for simple queries)"""
    
    search_request = EnhancedCPESearchRequest(
        query=q,
        vendor_filter=vendor,
        product_filter=product,
        version_filter=version,
        category_filter=category,
        include_deprecated=include_deprecated,
        limit=limit,
        offset=offset
    )
    
    return await enhanced_cpe_search(search_request, current_user, db)

@router.get("/product/{cpe_name_id}", response_model=EnhancedCPEProductResponse)
async def get_enhanced_cpe_product(
    cpe_name_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific CPE product"""
    try:
        cpe_manager = EnhancedCPEDatabaseManager(db)
        if not cpe_manager.load_cached_cpe_data():
            raise HTTPException(
                status_code=404,
                detail="Enhanced CPE data not available. Please run data ingestion first."
            )
        
        product = cpe_manager.get_product_by_id(cpe_name_id)
        if not product:
            raise HTTPException(status_code=404, detail="CPE product not found")
        
        return EnhancedCPEProductResponse(
            cpe_name=product.cpe_name,
            cpe_name_id=product.cpe_name_id,
            vendor=product.vendor,
            product=product.product,
            version=product.version,
            titles=[{"title": t.title, "lang": t.lang} for t in product.titles],
            references=[{"href": r.href, "type": r.ref_type, "content": r.content} 
                       for r in product.references],
            categories=list(product.categories),
            keywords=list(product.keywords),
            alternative_names=list(product.alternative_names),
            vendor_aliases=list(product.vendor_aliases),
            deprecated=product.deprecated,
            deprecation_date=product.deprecation_date.isoformat() if product.deprecation_date else None,
            deprecated_by=product.deprecated_by,
            last_modified=product.last_modified.isoformat() if product.last_modified else None,
            created=product.created.isoformat() if product.created else None,
            popularity_score=product.popularity_score
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting enhanced CPE product: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get product: {str(e)}")

@router.get("/vendors")
async def get_enhanced_cpe_vendors(
    query: Optional[str] = Query(None, description="Filter vendors by name"),
    limit: int = Query(50, description="Maximum number of vendors", ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of vendors with enhanced metadata"""
    try:
        cpe_manager = EnhancedCPEDatabaseManager(db)
        if not cpe_manager.load_cached_cpe_data():
            raise HTTPException(
                status_code=404,
                detail="Enhanced CPE data not available. Please run data ingestion first."
            )
        
        vendors = cpe_manager.get_vendors(query=query, limit=limit)
        
        return {
            "vendors": vendors,
            "total_count": len(vendors),
            "query": query
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting vendors: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get vendors: {str(e)}")

@router.get("/categories")
async def get_enhanced_cpe_categories(
    limit: int = Query(50, description="Maximum number of categories", ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of available product categories"""
    try:
        cpe_manager = EnhancedCPEDatabaseManager(db)
        if not cpe_manager.load_cached_cpe_data():
            raise HTTPException(
                status_code=404,
                detail="Enhanced CPE data not available. Please run data ingestion first."
            )
        
        categories = cpe_manager.get_categories(limit=limit)
        
        return {
            "categories": categories,
            "total_count": len(categories)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting categories: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get categories: {str(e)}")

@router.get("/suggestions")
async def get_search_suggestions(
    q: str = Query(..., description="Partial search query"),
    limit: int = Query(10, description="Maximum suggestions", ge=1, le=20),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get search suggestions for autocomplete"""
    try:
        cpe_manager = EnhancedCPEDatabaseManager(db)
        if not cpe_manager.load_cached_cpe_data():
            return {"suggestions": [], "query": q}
        
        suggestions = cpe_manager.get_search_suggestions(q, limit=limit)
        
        return {
            "suggestions": suggestions,
            "query": q,
            "count": len(suggestions)
        }
        
    except Exception as e:
        logger.error(f"Error getting search suggestions: {e}")
        return {"suggestions": [], "query": q, "error": str(e)}

@router.get("/debug")
async def debug_enhanced_cpe_search(
    q: str = Query(..., description="Search query to debug"),
    limit: int = Query(5, description="Number of debug results", ge=1, le=20),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Debug search functionality (development/testing only)"""
    try:
        cpe_manager = EnhancedCPEDatabaseManager(db)
        if not cpe_manager.load_cached_cpe_data():
            raise HTTPException(
                status_code=404,
                detail="Enhanced CPE data not available. Please run data ingestion first."
            )
        
        debug_info = cpe_manager.debug_search(q, limit=limit)
        
        return debug_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in debug search: {e}")
        raise HTTPException(status_code=500, detail=f"Debug search failed: {str(e)}")

@router.delete("/cache")
async def clear_enhanced_cpe_cache(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Clear CPE cache (forces re-ingestion on next request)"""
    try:
        cpe_manager = EnhancedCPEDatabaseManager(db)
        
        # Remove cache files
        cache_files_removed = []
        
        if cpe_manager.cache_file.exists():
            cpe_manager.cache_file.unlink()
            cache_files_removed.append(str(cpe_manager.cache_file))
        
        raw_cache = cpe_manager.cache_dir / "raw_cpe_data.json"
        if raw_cache.exists():
            raw_cache.unlink()
            cache_files_removed.append(str(raw_cache))
        
        return {
            "message": "Enhanced CPE cache cleared",
            "files_removed": cache_files_removed,
            "cache_directory": str(cpe_manager.cache_dir)
        }
        
    except Exception as e:
        logger.error(f"Error clearing CPE cache: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear cache: {str(e)}")

# Backward compatibility endpoints
@router.post("/legacy-search")
async def legacy_cpe_search_compatibility(
    search_data: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Legacy compatibility endpoint for existing frontend code"""
    try:
        # Convert legacy request to enhanced request
        enhanced_request = EnhancedCPESearchRequest(
            query=search_data.get('query', ''),
            vendor_filter=search_data.get('vendor_filter'),
            product_filter=search_data.get('product_filter'),
            version_filter=search_data.get('version_filter'),
            include_deprecated=search_data.get('include_deprecated', False),
            limit=search_data.get('limit', 20),
            offset=search_data.get('offset', 0)
        )
        
        # Use enhanced search
        result = await enhanced_cpe_search(enhanced_request, current_user, db)
        
        # Convert back to legacy format if needed
        legacy_products = []
        for product in result.products:
            legacy_product = {
                'cpe_name': product.cpe_name,
                'cpe_name_id': product.cpe_name_id,
                'vendor': product.vendor,
                'product': product.product,
                'version': product.version,
                'deprecated': product.deprecated,
                'title': product.titles[0]['title'] if product.titles else None,
                'description': product.titles[0]['title'] if product.titles else None,
                'references': [{'href': r['href']} for r in product.references],
                'last_modified': product.last_modified,
            }
            legacy_products.append(legacy_product)
        
        return {
            'products': legacy_products,
            'total_count': result.total_count,
            'search_query': result.search_query,
            'execution_time_ms': result.execution_time_ms
        }
        
    except Exception as e:
        logger.error(f"Error in legacy CPE search: {e}")
        raise HTTPException(status_code=500, detail=f"Legacy search failed: {str(e)}")