"""
Enhanced CPE Lookup API with CPE Dictionary 2.0 and CPE Match 2.0 Integration
app/api/enhanced_cpe_lookup.py

Complete API replacement for existing enhanced_cpe_lookup.py with full NIST integration.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import logging
import time
import asyncio

from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.services.enhanced_cpe_dictionary import EnhancedCPEDictionaryManager
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()

# Enhanced Pydantic Models
class EnhancedCPESearchRequest(BaseModel):
    """Enhanced search request with comprehensive filtering"""
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
    update: Optional[str] = None
    edition: Optional[str] = None
    language: Optional[str] = None
    sw_edition: Optional[str] = None
    target_sw: Optional[str] = None
    target_hw: Optional[str] = None
    other: Optional[str] = None
    
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
    """Enhanced search response with comprehensive metadata"""
    products: List[EnhancedCPEProductResponse]
    total_count: int
    search_query: str
    normalized_query: str
    filters_applied: Dict[str, Any]
    categories_found: List[str] = Field(default_factory=list)
    execution_time_ms: int
    search_suggestions: List[str] = Field(default_factory=list)

class CPEStatusResponse(BaseModel):
    """CPE database status with detailed information"""
    has_data: bool
    total_products: int
    total_matches: int = 0
    last_updated: Optional[str]
    cache_files: Dict[str, bool] = Field(default_factory=dict)
    categories_available: int = 0
    vendors_count: int = 0
    search_indices_built: bool = False

class CPEIngestionResponse(BaseModel):
    """Response for CPE data ingestion"""
    message: str
    started_at: str
    cpe_dictionary_products: int = 0
    cpe_matches: int = 0
    total_processing_time: float = 0
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    cache_files_created: List[str] = Field(default_factory=list)

class CPEMatchRequest(BaseModel):
    """Request for CPE matching"""
    vendor: str
    product: str
    version: Optional[str] = None

class CPEMatchResponse(BaseModel):
    """Response for CPE matching"""
    cpe_name: str
    match_criteria_id: str
    vulnerable: bool = False
    version_range: Optional[Dict[str, str]] = None
    affects_all_versions: bool = False

# API Endpoints

@router.get("/status", response_model=CPEStatusResponse)
async def get_enhanced_cpe_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get enhanced CPE database status"""
    try:
        cpe_manager = EnhancedCPEDictionaryManager(db)
        status = cpe_manager.get_status()
        
        return CPEStatusResponse(**status)
        
    except Exception as e:
        logger.error(f"Error getting CPE status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get CPE status: {str(e)}")

@router.post("/ingest", response_model=CPEIngestionResponse)
async def ingest_enhanced_cpe_data(
    background_tasks: BackgroundTasks,
    force_refresh: bool = Query(False, description="Force refresh of cached data"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Ingest CPE Dictionary 2.0 and CPE Match 2.0 data from NIST"""
    try:
        if current_user.role not in ["admin", "manager"]:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        cpe_manager = EnhancedCPEDictionaryManager(db)
        
        logger.info(f"Starting CPE data ingestion (force_refresh={force_refresh})")
        
        # Run ingestion
        stats = await cpe_manager.ingest_complete_cpe_data(force_refresh)
        
        return CPEIngestionResponse(
            message="CPE data ingestion completed" if not stats.get('errors') else "CPE data ingestion completed with errors",
            **stats
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in CPE ingestion: {e}")
        raise HTTPException(status_code=500, detail=f"CPE ingestion failed: {str(e)}")

@router.post("/search", response_model=EnhancedCPESearchResponse)
async def enhanced_cpe_search(
    search_request: EnhancedCPESearchRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Enhanced CPE search with comprehensive filtering and ranking"""
    try:
        cpe_manager = EnhancedCPEDictionaryManager(db)
        
        # Load data if not already loaded
        if not cpe_manager.load_cached_data():
            raise HTTPException(
                status_code=404,
                detail="Enhanced CPE data not available. Please run data ingestion first."
            )
        
        # Prepare filters
        filters = {}
        if search_request.vendor_filter:
            filters['vendor_filter'] = search_request.vendor_filter
        if search_request.product_filter:
            filters['product_filter'] = search_request.product_filter
        if search_request.version_filter:
            filters['version_filter'] = search_request.version_filter
        if search_request.category_filter:
            filters['category_filter'] = search_request.category_filter
        if search_request.include_deprecated:
            filters['include_deprecated'] = search_request.include_deprecated
        
        # Perform search
        search_result = cpe_manager.enhanced_search(
            query=search_request.query,
            filters=filters,
            limit=search_request.limit,
            offset=search_request.offset
        )
        
        return EnhancedCPESearchResponse(**search_result)
        
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
    try:
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
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in GET search: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

@router.get("/product/{cpe_name_id}", response_model=EnhancedCPEProductResponse)
async def get_enhanced_cpe_product(
    cpe_name_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific CPE product"""
    try:
        cpe_manager = EnhancedCPEDictionaryManager(db)
        if not cpe_manager.load_cached_data():
            raise HTTPException(
                status_code=404,
                detail="Enhanced CPE data not available. Please run data ingestion first."
            )
        
        product_data = cpe_manager.get_cpe_by_id(cpe_name_id)
        if not product_data:
            raise HTTPException(
                status_code=404,
                detail=f"CPE product with ID {cpe_name_id} not found"
            )
        
        return EnhancedCPEProductResponse(**product_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting CPE product: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get CPE product: {str(e)}")

@router.get("/categories")
async def get_enhanced_cpe_categories(
    limit: int = Query(50, description="Maximum categories", ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get available CPE categories"""
    try:
        cpe_manager = EnhancedCPEDictionaryManager(db)
        if not cpe_manager.load_cached_data():
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

@router.get("/vendors")
async def get_enhanced_cpe_vendors(
    limit: int = Query(100, description="Maximum vendors", ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get available CPE vendors"""
    try:
        cpe_manager = EnhancedCPEDictionaryManager(db)
        if not cpe_manager.load_cached_data():
            raise HTTPException(
                status_code=404,
                detail="Enhanced CPE data not available. Please run data ingestion first."
            )
        
        vendors = cpe_manager.get_vendors(limit=limit)
        
        return {
            "vendors": vendors,
            "total_count": len(vendors)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting vendors: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get vendors: {str(e)}")

@router.get("/suggestions")
async def get_search_suggestions(
    q: str = Query(..., description="Partial search query"),
    limit: int = Query(10, description="Maximum suggestions", ge=1, le=20),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get search suggestions for autocomplete"""
    try:
        cpe_manager = EnhancedCPEDictionaryManager(db)
        if not cpe_manager.load_cached_data():
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

@router.post("/match", response_model=List[CPEMatchResponse])
async def find_cpe_matches(
    match_request: CPEMatchRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Find CPE matches for a specific product (useful for vulnerability correlation)"""
    try:
        cpe_manager = EnhancedCPEDictionaryManager(db)
        if not cpe_manager.load_cached_data():
            raise HTTPException(
                status_code=404,
                detail="Enhanced CPE data not available. Please run data ingestion first."
            )
        
        matches = cpe_manager.find_cpe_matches_for_product(
            vendor=match_request.vendor,
            product=match_request.product,
            version=match_request.version
        )
        
        match_responses = []
        for match in matches:
            version_range = None
            if match.has_version_range:
                version_range = {}
                if match.version_start_including:
                    version_range['start_including'] = match.version_start_including
                if match.version_start_excluding:
                    version_range['start_excluding'] = match.version_start_excluding
                if match.version_end_including:
                    version_range['end_including'] = match.version_end_including
                if match.version_end_excluding:
                    version_range['end_excluding'] = match.version_end_excluding
            
            match_responses.append(CPEMatchResponse(
                cpe_name=match.cpe_name,
                match_criteria_id=match.match_criteria_id,
                vulnerable=match.vulnerable,
                version_range=version_range,
                affects_all_versions=match.affects_all_versions
            ))
        
        return match_responses
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error finding CPE matches: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to find CPE matches: {str(e)}")

@router.get("/debug")
async def debug_enhanced_cpe_search(
    q: str = Query(..., description="Search query to debug"),
    limit: int = Query(5, description="Number of debug results", ge=1, le=20),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Debug search functionality (development/testing only)"""
    try:
        cpe_manager = EnhancedCPEDictionaryManager(db)
        if not cpe_manager.load_cached_data():
            raise HTTPException(
                status_code=404,
                detail="Enhanced CPE data not available. Please run data ingestion first."
            )
        
        # Perform search with debug information
        search_result = cpe_manager.enhanced_search(q, limit=limit)
        
        # Add debug information
        debug_info = {
            "query": q,
            "normalized_query": search_result.get('normalized_query', ''),
            "execution_time_ms": search_result.get('execution_time_ms', 0),
            "total_count": search_result.get('total_count', 0),
            "results": search_result.get('products', [])[:limit],
            "search_indices_info": {
                "vendors_indexed": len(cpe_manager._vendor_index),
                "products_indexed": len(cpe_manager._product_index),
                "categories_indexed": len(cpe_manager._category_index),
                "keywords_indexed": len(cpe_manager._keyword_index)
            },
            "categories_found": search_result.get('categories_found', []),
            "suggestions": search_result.get('search_suggestions', [])
        }
        
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
        if current_user.role not in ["admin", "manager"]:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        cpe_manager = EnhancedCPEDictionaryManager(db)
        removed_files = cpe_manager.clear_cache()
        
        return {
            "message": "Enhanced CPE cache cleared",
            "files_removed": removed_files,
            "cache_directory": str(cpe_manager.cache_dir)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error clearing CPE cache: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear cache: {str(e)}")

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
        
        # Convert response to legacy format for backward compatibility
        legacy_products = []
        for product in result.products:
            legacy_product = {
                'cpe_name': product.cpe_name,
                'cpe_name_id': product.cpe_name_id,
                'vendor': product.vendor,
                'product': product.product,
                'version': product.version,
                'title': product.titles[0].get('title', '') if product.titles else '',
                'description': f"{product.vendor} {product.product}" if product.vendor and product.product else '',
                'deprecated': product.deprecated,
                'references': product.references,
                'popularity_score': product.popularity_score,
                'relevance_score': product.search_score or 0.0
            }
            legacy_products.append(legacy_product)
        
        return {
            'products': legacy_products,
            'total_count': result.total_count,
            'search_query': result.search_query,
            'execution_time_ms': result.execution_time_ms
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in legacy search: {e}")
        raise HTTPException(status_code=500, detail=f"Legacy search failed: {str(e)}")

@router.get("/analytics")
async def get_cpe_analytics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get CPE usage analytics (admin only)"""
    try:
        if current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")
        
        cpe_manager = EnhancedCPEDictionaryManager(db)
        if not cpe_manager.load_cached_data():
            return {"message": "No CPE data available"}
        
        # Basic analytics
        total_products = len(cpe_manager.cpe_products)
        deprecated_count = sum(1 for p in cpe_manager.cpe_products if p.deprecated)
        
        category_stats = {}
        for product in cpe_manager.cpe_products:
            for category in (product.categories or []):
                category_stats[category] = category_stats.get(category, 0) + 1
        
        vendor_stats = {}
        for product in cpe_manager.cpe_products:
            if product.vendor:
                vendor_stats[product.vendor] = vendor_stats.get(product.vendor, 0) + 1
        
        # Top categories and vendors
        top_categories = sorted(category_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        top_vendors = sorted(vendor_stats.items(), key=lambda x: x[1], reverse=True)[:20]
        
        return {
            "total_products": total_products,
            "deprecated_products": deprecated_count,
            "active_products": total_products - deprecated_count,
            "total_categories": len(category_stats),
            "total_vendors": len(vendor_stats),
            "total_matches": len(cpe_manager.cpe_matches),
            "top_categories": top_categories,
            "top_vendors": top_vendors,
            "cache_status": cpe_manager.get_status()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting analytics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get analytics: {str(e)}")

@router.get("/export")
async def export_cpe_data(
    format: str = Query("json", description="Export format: json, csv"),
    limit: int = Query(1000, description="Maximum records", ge=1, le=10000),
    category_filter: Optional[str] = Query(None, description="Filter by category"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Export CPE data in various formats"""
    try:
        if current_user.role not in ["admin", "manager"]:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        cpe_manager = EnhancedCPEDictionaryManager(db)
        if not cpe_manager.load_cached_data():
            raise HTTPException(
                status_code=404,
                detail="Enhanced CPE data not available. Please run data ingestion first."
            )
        
        # Filter products
        products = cpe_manager.cpe_products[:limit]
        if category_filter:
            products = [
                p for p in products 
                if category_filter.lower() in [c.lower() for c in (p.categories or [])]
            ]
        
        if format.lower() == "csv":
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'CPE Name', 'CPE Name ID', 'Vendor', 'Product', 'Version',
                'Categories', 'Deprecated', 'Last Modified', 'Popularity Score'
            ])
            
            # Write data
            for product in products:
                writer.writerow([
                    product.cpe_name,
                    product.cpe_name_id,
                    product.vendor,
                    product.product,
                    product.version,
                    ','.join(product.categories or []),
                    product.deprecated,
                    product.last_modified.isoformat() if product.last_modified else '',
                    product.popularity_score
                ])
            
            from fastapi.responses import StreamingResponse
            
            output.seek(0)
            return StreamingResponse(
                io.BytesIO(output.getvalue().encode('utf-8')),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=cpe_export_{len(products)}.csv"}
            )
        
        else:  # JSON format
            export_data = {
                "export_info": {
                    "timestamp": time.time(),
                    "total_records": len(products),
                    "format": "json",
                    "filters": {
                        "category_filter": category_filter,
                        "limit": limit
                    }
                },
                "products": []
            }
            
            for product in products:
                product_data = {
                    "cpe_name": product.cpe_name,
                    "cpe_name_id": product.cpe_name_id,
                    "vendor": product.vendor,
                    "product": product.product,
                    "version": product.version,
                    "categories": product.categories,
                    "deprecated": product.deprecated,
                    "last_modified": product.last_modified.isoformat() if product.last_modified else None,
                    "popularity_score": product.popularity_score,
                    "titles": product.titles,
                    "references": product.references
                }
                export_data["products"].append(product_data)
            
            return export_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting CPE data: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to export data: {str(e)}")

@router.post("/validate")
async def validate_cpe_name(
    cpe_name: str = Query(..., description="CPE name to validate"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Validate CPE name format and check if it exists"""
    try:
        import re
        
        # Validate CPE 2.3 format
        cpe_pattern = r'^cpe:2\.3:[aho\*]:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$'
        
        validation_result = {
            "cpe_name": cpe_name,
            "valid_format": bool(re.match(cpe_pattern, cpe_name)),
            "exists_in_database": False,
            "suggestions": [],
            "parsed_components": None
        }
        
        if validation_result["valid_format"]:
            # Parse components
            parts = cpe_name.split(':')
            validation_result["parsed_components"] = {
                "part": parts[2],
                "vendor": parts[3],
                "product": parts[4],
                "version": parts[5],
                "update": parts[6],
                "edition": parts[7],
                "language": parts[8],
                "sw_edition": parts[9],
                "target_sw": parts[10],
                "target_hw": parts[11],
                "other": parts[12]
            }
            
            # Check if exists in database
            cpe_manager = EnhancedCPEDictionaryManager(db)
            if cpe_manager.load_cached_data():
                for product in cpe_manager.cpe_products:
                    if product.cpe_name == cpe_name:
                        validation_result["exists_in_database"] = True
                        break
                
                # Generate suggestions if not found
                if not validation_result["exists_in_database"]:
                    search_query = f"{parts[3]} {parts[4]}".replace('*', '').strip()
                    if search_query:
                        search_results = cpe_manager.enhanced_search(search_query, limit=5)
                        validation_result["suggestions"] = [
                            {
                                "cpe_name": p["cpe_name"],
                                "vendor": p["vendor"],
                                "product": p["product"],
                                "version": p["version"]
                            }
                            for p in search_results.get("products", [])
                        ]
        
        return validation_result
        
    except Exception as e:
        logger.error(f"Error validating CPE name: {e}")
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")

@router.get("/statistics")
async def get_cpe_statistics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed CPE database statistics"""
    try:
        cpe_manager = EnhancedCPEDictionaryManager(db)
        if not cpe_manager.load_cached_data():
            return {
                "message": "No CPE data available",
                "statistics": {
                    "total_products": 0,
                    "total_matches": 0,
                    "last_updated": None
                }
            }
        
        # Calculate statistics
        total_products = len(cpe_manager.cpe_products)
        deprecated_count = sum(1 for p in cpe_manager.cpe_products if p.deprecated)
        
        # Version distribution
        version_types = {"specific": 0, "wildcard": 0, "range": 0}
        for product in cpe_manager.cpe_products:
            if product.version == '*':
                version_types["wildcard"] += 1
            elif '.' in product.version and product.version != '*':
                version_types["specific"] += 1
            else:
                version_types["range"] += 1
        
        # Part type distribution (application, OS, hardware)
        part_distribution = {"a": 0, "o": 0, "h": 0}
        for product in cpe_manager.cpe_products:
            part = product.cpe_name.split(':')[2] if ':' in product.cpe_name else 'unknown'
            if part in part_distribution:
                part_distribution[part] += 1
        
        # Category distribution
        category_counts = {}
        for product in cpe_manager.cpe_products:
            for category in (product.categories or []):
                category_counts[category] = category_counts.get(category, 0) + 1
        
        # Vendor distribution (top 20)
        vendor_counts = {}
        for product in cpe_manager.cpe_products:
            if product.vendor and product.vendor != '*':
                vendor_counts[product.vendor] = vendor_counts.get(product.vendor, 0) + 1
        
        top_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        
        # Match statistics
        match_stats = {
            "total_matches": len(cpe_manager.cpe_matches),
            "vulnerable_matches": sum(1 for m in cpe_manager.cpe_matches if m.vulnerable),
            "version_range_matches": sum(1 for m in cpe_manager.cpe_matches if m.has_version_range)
        }
        
        statistics = {
            "overview": {
                "total_products": total_products,
                "deprecated_products": deprecated_count,
                "active_products": total_products - deprecated_count,
                "total_categories": len(category_counts),
                "total_vendors": len(vendor_counts)
            },
            "distributions": {
                "by_part_type": {
                    "applications": part_distribution["a"],
                    "operating_systems": part_distribution["o"],
                    "hardware": part_distribution["h"]
                },
                "by_version_type": version_types,
                "by_category": dict(sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:15]),
                "top_vendors": dict(top_vendors)
            },
            "match_data": match_stats,
            "cache_info": {
                "last_updated": cpe_manager._get_cache_timestamp(),
                "search_indices_built": bool(cpe_manager._cpe_name_index),
                "indexed_vendors": len(cpe_manager._vendor_index),
                "indexed_products": len(cpe_manager._product_index),
                "indexed_categories": len(cpe_manager._category_index),
                "indexed_keywords": len(cpe_manager._keyword_index)
            }
        }
        
        return {"statistics": statistics}
        
    except Exception as e:
        logger.error(f"Error getting CPE statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")

@router.get("/health")
async def cpe_health_check():
    """Simple health check for Enhanced CPE service"""
    return {
        "status": "healthy",
        "service": "Enhanced CPE Dictionary and Matching",
        "version": "2.0",
        "timestamp": time.time(),
        "nist_feeds": {
            "cpe_dictionary": "2.0",
            "cpe_match": "2.0"
        }
    }

@router.get("/ingestion/status")
async def get_ingestion_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get status of the last ingestion process"""
    try:
        cpe_manager = EnhancedCPEDictionaryManager(db)
        
        # Check for ingestion log or status file
        import os
        from pathlib import Path
        
        status_file = cpe_manager.cache_dir / "last_ingestion_status.json"
        
        if status_file.exists():
            try:
                with open(status_file, 'r') as f:
                    import json
                    last_status = json.load(f)
                return {
                    "last_ingestion": last_status,
                    "current_status": cpe_manager.get_status()
                }
            except Exception as e:
                logger.error(f"Failed to read ingestion status: {e}")
        
        return {
            "message": "No previous ingestion found",
            "current_status": cpe_manager.get_status()
        }
        
    except Exception as e:
        logger.error(f"Error getting ingestion status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get ingestion status: {str(e)}")

@router.get("/config")
async def get_cpe_configuration(
    current_user: User = Depends(get_current_user)
):
    """Get CPE system configuration (admin only)"""
    try:
        if current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")
        
        config = {
            "cache_settings": {
                "cpe_cache_dir": settings.CPE_CACHE_DIR,
                "include_deprecated": settings.CPE_INCLUDE_DEPRECATED,
                "auto_refresh_hours": settings.CPE_AUTO_REFRESH_HOURS,
                "search_timeout_seconds": settings.CPE_SEARCH_TIMEOUT_SECONDS,
                "max_search_results": settings.CPE_MAX_SEARCH_RESULTS
            },
            "data_sources": {
                "cpe_dictionary_url": settings.CPE_DICTIONARY_URL,
                "cpe_match_url": settings.CPE_MATCH_URL
            },
            "correlation_settings": {
                "confidence_threshold": settings.CPE_CORRELATION_CONFIDENCE_THRESHOLD,
                "enabled": settings.ASSET_CORRELATION_ENABLED,
                "batch_size": settings.ASSET_CORRELATION_BATCH_SIZE
            },
            "performance_settings": {
                "http_timeout_seconds": settings.HTTP_TIMEOUT_SECONDS,
                "async_concurrency_limit": settings.ASYNC_CONCURRENCY_LIMIT,
                "background_ingestion": settings.ENABLE_BACKGROUND_INGESTION
            }
        }
        
        return {"configuration": config}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting configuration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get configuration: {str(e)}")

@router.get("/diagnostic")
async def run_cpe_diagnostic(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Run diagnostic checks on CPE system (admin only)"""
    try:
        if current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")
        
        diagnostic_results = {
            "timestamp": time.time(),
            "checks": {},
            "recommendations": []
        }
        
        cpe_manager = EnhancedCPEDictionaryManager(db)
        
        # Check 1: Cache directory accessibility
        try:
            import os
            cache_dir = cpe_manager.cache_dir
            cache_accessible = os.path.exists(cache_dir) and os.access(cache_dir, os.R_OK | os.W_OK)
            diagnostic_results["checks"]["cache_directory"] = {
                "status": "pass" if cache_accessible else "fail",
                "path": str(cache_dir),
                "readable": os.access(cache_dir, os.R_OK) if os.path.exists(cache_dir) else False,
                "writable": os.access(cache_dir, os.W_OK) if os.path.exists(cache_dir) else False
            }
            
            if not cache_accessible:
                diagnostic_results["recommendations"].append("Fix cache directory permissions")
                
        except Exception as e:
            diagnostic_results["checks"]["cache_directory"] = {"status": "error", "error": str(e)}
        
        # Check 2: Data availability
        try:
            data_loaded = cpe_manager.load_cached_data()
            diagnostic_results["checks"]["data_availability"] = {
                "status": "pass" if data_loaded else "warning",
                "cached_data_loaded": data_loaded,
                "products_count": len(cpe_manager.cpe_products) if data_loaded else 0,
                "matches_count": len(cpe_manager.cpe_matches) if data_loaded else 0
            }
            
            if not data_loaded:
                diagnostic_results["recommendations"].append("Run CPE data ingestion")
                
        except Exception as e:
            diagnostic_results["checks"]["data_availability"] = {"status": "error", "error": str(e)}
        
        # Check 3: Search indices
        try:
            indices_built = bool(cpe_manager._cpe_name_index) if hasattr(cpe_manager, '_cpe_name_index') else False
            diagnostic_results["checks"]["search_indices"] = {
                "status": "pass" if indices_built else "warning",
                "indices_built": indices_built,
                "vendor_index_size": len(cpe_manager._vendor_index) if indices_built else 0,
                "product_index_size": len(cpe_manager._product_index) if indices_built else 0
            }
            
            if not indices_built:
                diagnostic_results["recommendations"].append("Rebuild search indices")
                
        except Exception as e:
            diagnostic_results["checks"]["search_indices"] = {"status": "error", "error": str(e)}
        
        # Check 4: Network connectivity to NIST
        try:
            import httpx
            
            async def check_connectivity():
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        response = await client.head("https://nvd.nist.gov/feeds/json/cpe/2.0/")
                        return response.status_code == 200
                except:
                    return False
            
            connectivity = await check_connectivity()
            diagnostic_results["checks"]["network_connectivity"] = {
                "status": "pass" if connectivity else "warning",
                "nist_feeds_accessible": connectivity
            }
            
            if not connectivity:
                diagnostic_results["recommendations"].append("Check network connectivity to NIST feeds")
                
        except Exception as e:
            diagnostic_results["checks"]["network_connectivity"] = {"status": "error", "error": str(e)}
        
        # Check 5: Configuration validation
        try:
            from app.core.config import validate_environment
            config_issues = validate_environment()
            diagnostic_results["checks"]["configuration"] = {
                "status": "pass" if not config_issues else "warning",
                "issues": config_issues
            }
            
            if config_issues:
                diagnostic_results["recommendations"].extend([f"Fix config: {issue}" for issue in config_issues])
                
        except Exception as e:
            diagnostic_results["checks"]["configuration"] = {"status": "error", "error": str(e)}
        
        # Overall status
        check_statuses = [check.get("status", "error") for check in diagnostic_results["checks"].values()]
        if "error" in check_statuses:
            diagnostic_results["overall_status"] = "error"
        elif "fail" in check_statuses:
            diagnostic_results["overall_status"] = "fail"
        elif "warning" in check_statuses:
            diagnostic_results["overall_status"] = "warning"
        else:
            diagnostic_results["overall_status"] = "pass"
        
        return diagnostic_results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error running diagnostic: {e}")
        raise HTTPException(status_code=500, detail=f"Diagnostic failed: {str(e)}")

@router.post("/bulk-search")
async def bulk_cpe_search(
    request: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Bulk CPE search for multiple queries"""
    try:
        queries = request.get('queries', [])
        limit_per_query = request.get('limit_per_query', 10)
        
        if not queries or not isinstance(queries, list):
            raise HTTPException(status_code=400, detail="queries must be a non-empty list")
        
        if len(queries) > 20:
            raise HTTPException(status_code=400, detail="Maximum 20 queries allowed")
        
        if not isinstance(limit_per_query, int) or limit_per_query < 1 or limit_per_query > 50:
            raise HTTPException(status_code=400, detail="limit_per_query must be between 1 and 50")
        
        cpe_manager = EnhancedCPEDictionaryManager(db)
        if not cpe_manager.load_cached_data():
            raise HTTPException(
                status_code=404,
                detail="Enhanced CPE data not available. Please run data ingestion first."
            )
        
        results = {}
        total_time = 0
        
        for query in queries:
            if query and isinstance(query, str) and query.strip():
                search_result = cpe_manager.enhanced_search(
                    query=query.strip(),
                    limit=limit_per_query
                )
                results[query] = {
                    "products": search_result.get('products', []),
                    "total_count": search_result.get('total_count', 0),
                    "execution_time_ms": search_result.get('execution_time_ms', 0)
                }
                total_time += search_result.get('execution_time_ms', 0)
        
        return {
            "results": results,
            "queries_processed": len(results),
            "total_execution_time_ms": total_time,
            "average_time_per_query_ms": total_time / len(results) if results else 0
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in bulk search: {e}")
        raise HTTPException(status_code=500, detail=f"Bulk search failed: {str(e)}")

@router.post("/test/search-performance")
async def test_search_performance(
    request: Dict[str, Any],
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Test search performance with multiple queries (development/testing)"""
    try:
        if not settings.DEBUG and current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Available in debug mode or for admins only")
        
        test_queries = request.get('test_queries', [])
        iterations = request.get('iterations', 10)
        
        if not test_queries or not isinstance(test_queries, list):
            raise HTTPException(status_code=400, detail="test_queries must be a non-empty list")
        
        if not isinstance(iterations, int) or iterations < 1 or iterations > 100:
            raise HTTPException(status_code=400, detail="iterations must be between 1 and 100")
        
        cpe_manager = EnhancedCPEDictionaryManager(db)
        if not cpe_manager.load_cached_data():
            raise HTTPException(
                status_code=404,
                detail="Enhanced CPE data not available"
            )
        
        performance_results = []
        
        for query in test_queries[:10]:  # Limit to 10 queries
            if not query or not isinstance(query, str):
                continue
                
            query_results = {
                "query": query,
                "iterations": iterations,
                "execution_times": [],
                "avg_execution_time": 0,
                "min_execution_time": 0,
                "max_execution_time": 0,
                "results_count": 0
            }
            
            for _ in range(iterations):
                start_time = time.time()
                search_result = cpe_manager.enhanced_search(query, limit=20)
                execution_time = (time.time() - start_time) * 1000  # Convert to milliseconds
                
                query_results["execution_times"].append(execution_time)
                query_results["results_count"] = search_result.get("total_count", 0)
            
            # Calculate statistics
            execution_times = query_results["execution_times"]
            if execution_times:
                query_results["avg_execution_time"] = sum(execution_times) / len(execution_times)
                query_results["min_execution_time"] = min(execution_times)
                query_results["max_execution_time"] = max(execution_times)
            
            performance_results.append(query_results)
        
        # Overall statistics
        all_times = [time for result in performance_results for time in result["execution_times"]]
        overall_stats = {
            "total_queries_tested": len([q for q in test_queries if q and isinstance(q, str)]),
            "total_iterations": len(all_times),
            "overall_avg_time": sum(all_times) / len(all_times) if all_times else 0,
            "overall_min_time": min(all_times) if all_times else 0,
            "overall_max_time": max(all_times) if all_times else 0,
            "queries_per_second": 1000 / (sum(all_times) / len(all_times)) if all_times else 0
        }
        
        return {
            "performance_test_results": performance_results,
            "overall_statistics": overall_stats,
            "timestamp": time.time()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in performance test: {e}")
        raise HTTPException(status_code=500, detail=f"Performance test failed: {str(e)}")