"""
CPE Lookup API Endpoints - Manual Service Creation with CPE Reference
app/api/cpe_lookup.py
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, Form
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
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

from app.services.cpe_nlp_processor import CPEQueryProcessor, CPEQuery

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
    
class EnhancedCPESearchRequest(BaseModel):
    """Enhanced CPE search request with natural language support"""
    query: str = Field(..., description="Natural language or structured query")
    search_mode: str = Field(default="smart", description="Search mode: 'smart', 'simple', 'advanced'")
    max_results: int = Field(default=20, ge=1, le=100)
    include_deprecated: bool = Field(default=False)
    include_suggestions: bool = Field(default=True, description="Include alternative suggestions")
    confidence_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    
    # Advanced filters (optional)
    vendor_filter: Optional[str] = None
    product_filter: Optional[str] = None
    version_filter: Optional[str] = None
    part_filter: Optional[str] = Field(None, description="CPE part: 'a', 'o', or 'h'")

class CPEProductEnhanced(BaseModel):
    """Enhanced CPE product response"""
    cpe_name: str
    cpe_name_id: str
    vendor: str
    product: str
    version: str
    title: Optional[str]
    description: Optional[str]
    last_modified: Optional[str]
    deprecated: bool
    references: Optional[List[Dict]]
    
    # Enhanced fields
    popularity_score: float = Field(0.0, description="Popularity/usage score")
    relevance_score: float = Field(0.0, description="Relevance to search query")
    security_risk_level: str = Field("unknown", description="General security risk assessment")
    category: Optional[str] = Field(None, description="Software category")
    vendor_verified: bool = Field(False, description="Whether vendor information is verified")

class SearchSuggestion(BaseModel):
    """Search suggestion for improving queries"""
    suggestion: str
    reason: str
    confidence: float

class QueryUnderstanding(BaseModel):
    """Explanation of how the query was understood"""
    original_query: str
    extracted_components: Dict[str, Optional[str]]
    confidence: float
    explanation: str
    extracted_terms: List[str]

class EnhancedCPESearchResponse(BaseModel):
    """Enhanced CPE search response"""
    products: List[CPEProductEnhanced]
    total_count: int
    search_query: str
    processed_query: Optional[Dict] = None
    search_mode: str
    execution_time_ms: int
    confidence_score: float
    suggestions: List[SearchSuggestion] = []
    filters_applied: Dict[str, Any]
    
    # Query understanding
    query_understanding: Optional[QueryUnderstanding] = None
    alternative_queries: List[str] = []

class AutocompleteResponse(BaseModel):
    """Autocomplete suggestion response"""
    suggestions: List[str]
    popular_products: List[Dict[str, str]]
    query_hints: List[str]


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
    
@router.post("/enhanced-search", response_model=EnhancedCPESearchResponse)
async def enhanced_cpe_search(
    request: EnhancedCPESearchRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Enhanced CPE search with natural language processing"""
    start_time = time.time()
    
    try:
        # Initialize processors
        cpe_manager = CPEDatabaseManager(db)
        nlp_processor = CPEQueryProcessor()
        
        # Check if CPE data is available
        if not cpe_manager.load_cached_cpe_data():
            raise HTTPException(
                status_code=404,
                detail="CPE data not available. Please run data ingestion first."
            )
        
        # Process query based on search mode
        if request.search_mode == "smart":
            # Use NLP to understand the query
            processed_query = nlp_processor.process_query(request.query)
            search_params = nlp_processor.generate_cpe_search_params(processed_query)
            
            # Override with explicit filters if provided
            if request.vendor_filter:
                search_params['vendor_filter'] = request.vendor_filter
            if request.product_filter:
                search_params['product_filter'] = request.product_filter
            if request.version_filter:
                search_params['version_filter'] = request.version_filter
                
        elif request.search_mode == "advanced":
            # Use structured search parameters
            search_params = {
                'query': request.query,
                'vendor_filter': request.vendor_filter,
                'product_filter': request.product_filter,
                'version_filter': request.version_filter,
                'limit': request.max_results,
                'include_deprecated': request.include_deprecated
            }
            processed_query = None
            
        else:  # simple mode
            # Direct search with minimal processing
            search_params = {
                'query': request.query,
                'limit': request.max_results,
                'include_deprecated': request.include_deprecated
            }
            processed_query = None
        
        # Perform the search
        results, total_count = cpe_manager.search_products(**search_params)
        
        # Enhanced processing of results
        enhanced_products = []
        for cpe_product in results:
            # Calculate relevance score
            relevance_score = _calculate_relevance_score(
                cpe_product, request.query, processed_query
            )
            
            # Skip results below confidence threshold
            if relevance_score < request.confidence_threshold:
                continue
            
            # Get English title
            title = None
            for t in cpe_product.titles:
                if t.get('lang') == 'en':
                    title = t.get('title')
                    break
            
            # Enhanced product information
            enhanced_product = CPEProductEnhanced(
                cpe_name=cpe_product.cpe_name,
                cpe_name_id=cpe_product.cpe_name_id,
                vendor=cpe_product.vendor,
                product=cpe_product.product,
                version=cpe_product.version,
                title=title,
                description=title,
                last_modified=cpe_product.last_modified.isoformat() if cpe_product.last_modified else None,
                deprecated=cpe_product.deprecated,
                references=cpe_product.references,
                popularity_score=_calculate_popularity_score(cpe_product),
                relevance_score=relevance_score,
                security_risk_level=_assess_security_risk(cpe_product),
                category=_categorize_software(cpe_product),
                vendor_verified=_is_vendor_verified(cpe_product.vendor)
            )
            
            enhanced_products.append(enhanced_product)
        
        # Sort by relevance score
        enhanced_products.sort(key=lambda x: x.relevance_score, reverse=True)
        
        # Generate suggestions if requested
        suggestions = []
        if request.include_suggestions and len(enhanced_products) < 5:
            suggestions = _generate_search_suggestions(
                request.query, processed_query, enhanced_products
            )
        
        # Generate alternative queries
        alternative_queries = []
        if processed_query and processed_query.confidence < 0.7:
            alternative_queries = _generate_alternative_queries(processed_query)
        
        # Calculate overall confidence
        overall_confidence = _calculate_overall_confidence(
            processed_query, enhanced_products, total_count
        )
        
        # Create query understanding
        query_understanding = None
        if processed_query:
            query_understanding = QueryUnderstanding(
                original_query=processed_query.original_query,
                extracted_components={
                    "vendor": processed_query.vendor,
                    "product": processed_query.product,
                    "version": processed_query.version,
                    "type": processed_query.part
                },
                confidence=processed_query.confidence,
                explanation=nlp_processor.explain_query(processed_query),
                extracted_terms=processed_query.extracted_terms
            )
        
        execution_time = int((time.time() - start_time) * 1000)
        
        return EnhancedCPESearchResponse(
            products=enhanced_products[:request.max_results],
            total_count=len(enhanced_products),
            search_query=request.query,
            processed_query=processed_query.__dict__ if processed_query else None,
            search_mode=request.search_mode,
            execution_time_ms=execution_time,
            confidence_score=overall_confidence,
            suggestions=suggestions,
            filters_applied={
                "vendor_filter": search_params.get('vendor_filter'),
                "product_filter": search_params.get('product_filter'),
                "version_filter": search_params.get('version_filter'),
                "include_deprecated": request.include_deprecated,
                "confidence_threshold": request.confidence_threshold
            },
            query_understanding=query_understanding,
            alternative_queries=alternative_queries
        )
        
    except Exception as e:
        logger.error(f"Enhanced CPE search failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

@router.get("/autocomplete", response_model=AutocompleteResponse)
async def get_autocomplete_suggestions(
    query: str = Query(..., description="Partial query for suggestions"),
    limit: int = Query(default=10, ge=1, le=20),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get autocomplete suggestions for search input"""
    try:
        cpe_manager = CPEDatabaseManager(db)
        if not cpe_manager.load_cached_cpe_data():
            return AutocompleteResponse(
                suggestions=[],
                popular_products=[],
                query_hints=[]
            )
        
        # Generate suggestions based on query
        suggestions = []
        query_lower = query.lower()
        
        # Add vendor suggestions
        common_vendors = ['apache', 'microsoft', 'oracle', 'google', 'nginx', 'mysql', 'postgresql', 'mongodb']
        for vendor in common_vendors:
            if vendor.startswith(query_lower):
                suggestions.append(vendor.title())
        
        # Add product suggestions
        common_products = [
            'Apache HTTP Server', 'Nginx', 'MySQL', 'PostgreSQL', 'MongoDB',
            'Redis', 'Elasticsearch', 'Windows Server', 'Linux', 'Docker'
        ]
        for product in common_products:
            if query_lower in product.lower():
                suggestions.append(product)
        
        # Popular products with categories
        popular_products = [
            {"name": "Apache HTTP Server", "category": "Web Server"},
            {"name": "Nginx", "category": "Web Server"},
            {"name": "MySQL", "category": "Database"},
            {"name": "PostgreSQL", "category": "Database"},
            {"name": "Microsoft Windows Server", "category": "Operating System"},
            {"name": "Docker", "category": "Container Platform"}
        ]
        
        # Query hints
        query_hints = [
            "Try product names like 'apache', 'nginx', 'mysql'",
            "Include version numbers: 'apache 2.4'",
            "Use vendor names: 'microsoft', 'oracle', 'google'",
            "Search by category: 'web server', 'database', 'cms'"
        ]
        
        return AutocompleteResponse(
            suggestions=suggestions[:limit],
            popular_products=popular_products,
            query_hints=query_hints
        )
        
    except Exception as e:
        logger.error(f"Failed to generate autocomplete suggestions: {e}")
        return AutocompleteResponse(
            suggestions=[],
            popular_products=[],
            query_hints=[]
        )

@router.post("/parse-query")
async def parse_natural_language_query(
    query: str = Form(..., description="Natural language query to parse"),
    current_user: User = Depends(get_current_user)
):
    """Parse a natural language query and return understanding"""
    try:
        nlp_processor = CPEQueryProcessor()
        processed_query = nlp_processor.process_query(query)
        
        return {
            "original_query": query,
            "extracted_components": {
                "vendor": processed_query.vendor,
                "product": processed_query.product,
                "version": processed_query.version,
                "type": processed_query.part
            },
            "confidence": processed_query.confidence,
            "extracted_terms": processed_query.extracted_terms,
            "explanation": nlp_processor.explain_query(processed_query),
            "suggestions": nlp_processor.generate_suggestions(processed_query),
            "search_params": nlp_processor.generate_cpe_search_params(processed_query)
        }
        
    except Exception as e:
        logger.error(f"Failed to parse query: {e}")
        raise HTTPException(status_code=500, detail=f"Query parsing failed: {str(e)}")

# Helper functions - add these to the end of your cpe_lookup.py file

def _calculate_relevance_score(cpe_product, original_query: str, processed_query=None) -> float:
    """Calculate relevance score for a CPE product"""
    score = 0.0
    query_lower = original_query.lower()
    
    # Exact matches get highest score
    if query_lower in cpe_product.product.lower():
        score += 0.5
    if query_lower in cpe_product.vendor.lower():
        score += 0.3
    
    # Partial matches
    query_words = query_lower.split()
    for word in query_words:
        if word in cpe_product.product.lower():
            score += 0.2
        if word in cpe_product.vendor.lower():
            score += 0.1
    
    # Boost for processed query matches
    if processed_query:
        if processed_query.vendor and processed_query.vendor.lower() in cpe_product.vendor.lower():
            score += 0.3
        if processed_query.product and processed_query.product.lower() in cpe_product.product.lower():
            score += 0.4
        if processed_query.version and processed_query.version in cpe_product.version:
            score += 0.2
    
    # Boost for non-deprecated products
    if not cpe_product.deprecated:
        score += 0.1
    
    # Boost for recent products (if last_modified exists)
    if cpe_product.last_modified:
        # Implementation would check recency
        score += 0.05
    
    return min(score, 1.0)

def _calculate_popularity_score(cpe_product) -> float:
    """Calculate popularity score based on various factors"""
    # This would typically use real usage data
    common_products = {
        'apache': 0.95,
        'nginx': 0.90,
        'mysql': 0.85,
        'postgresql': 0.80,
        'mongodb': 0.75,
        'redis': 0.70,
        'elasticsearch': 0.65,
        'docker': 0.85,
        'kubernetes': 0.75
    }
    
    vendor_score = common_products.get(cpe_product.vendor.lower(), 0.5)
    product_score = common_products.get(cpe_product.product.lower(), 0.5)
    
    return max(vendor_score, product_score)

def _assess_security_risk(cpe_product) -> str:
    """Assess general security risk level"""
    # This would integrate with vulnerability databases
    if cpe_product.deprecated:
        return "high"
    
    # Check for known high-risk software categories
    high_risk_keywords = ['server', 'daemon', 'service', 'web']
    medium_risk_keywords = ['database', 'framework', 'runtime']
    
    product_lower = cpe_product.product.lower()
    
    if any(keyword in product_lower for keyword in high_risk_keywords):
        return "medium"
    elif any(keyword in product_lower for keyword in medium_risk_keywords):
        return "medium"
    
    return "low"

def _categorize_software(cpe_product) -> str:
    """Categorize software type"""
    categories = {
        'web_server': ['server', 'httpd', 'nginx', 'apache', 'iis'],
        'database': ['mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch'],
        'operating_system': ['windows', 'linux', 'ubuntu', 'centos', 'rhel'],
        'browser': ['chrome', 'firefox', 'safari', 'edge'],
        'development': ['java', 'python', 'node', 'php', 'ruby'],
        'container': ['docker', 'kubernetes', 'containerd'],
        'cms': ['wordpress', 'drupal', 'joomla'],
        'framework': ['spring', 'django', 'flask', 'rails']
    }
    
    product_lower = cpe_product.product.lower()
    vendor_lower = cpe_product.vendor.lower()
    
    for category, keywords in categories.items():
        if any(keyword in product_lower or keyword in vendor_lower for keyword in keywords):
            return category.replace('_', ' ').title()
    
    return "Other"

def _is_vendor_verified(vendor: str) -> bool:
    """Check if vendor is verified/trusted"""
    verified_vendors = {
        'apache', 'microsoft', 'oracle', 'google', 'nginx', 'postgresql',
        'mysql', 'mongodb', 'redis', 'elastic', 'docker', 'canonical',
        'mozilla', 'ibm', 'redhat', 'cisco', 'vmware', 'citrix'
    }
    return vendor.lower() in verified_vendors

def _generate_search_suggestions(query: str, processed_query, results) -> List[SearchSuggestion]:
    """Generate suggestions to improve search results"""
    suggestions = []
    
    if len(results) == 0:
        suggestions.append(SearchSuggestion(
            suggestion=f"Try searching for just '{query.split()[0]}' without version numbers",
            reason="No results found - try broader search",
            confidence=0.8
        ))
        
        suggestions.append(SearchSuggestion(
            suggestion="Include the vendor name (e.g., 'Apache HTTP Server' instead of just 'web server')",
            reason="Vendor names help identify specific products",
            confidence=0.7
        ))
    
    if processed_query and processed_query.confidence < 0.5:
        suggestions.append(SearchSuggestion(
            suggestion="Try using more specific product names",
            reason="Query understanding was low",
            confidence=0.7
        ))
        
        if not processed_query.version:
            suggestions.append(SearchSuggestion(
                suggestion="Consider adding a version number (e.g., 'nginx 1.18')",
                reason="Version numbers help find exact matches",
                confidence=0.6
            ))
    
    if len(query.split()) == 1:
        suggestions.append(SearchSuggestion(
            suggestion="Try using multiple words to describe the software",
            reason="Single-word searches can be ambiguous",
            confidence=0.6
        ))
    
    return suggestions

def _generate_alternative_queries(processed_query) -> List[str]:
    """Generate alternative query suggestions"""
    alternatives = []
    
    if processed_query.vendor and processed_query.product:
        alternatives.append(f"{processed_query.vendor} {processed_query.product}")
    
    if processed_query.product:
        alternatives.append(processed_query.product)
        
        # Add common variations
        if processed_query.product == "http_server":
            alternatives.extend(["web server", "apache"])
        elif processed_query.product == "mysql":
            alternatives.extend(["mysql database", "mysql server"])
    
    if processed_query.vendor:
        alternatives.append(processed_query.vendor)
    
    return list(set(alternatives))  # Remove duplicates

def _calculate_overall_confidence(processed_query, results, total_count) -> float:
    """Calculate overall search confidence"""
    confidence = 0.5  # Base confidence
    
    if processed_query:
        confidence = processed_query.confidence
    
    # Adjust based on result count
    if len(results) > 5:
        confidence += 0.2
    elif len(results) == 0:
        confidence = 0.1
    
    # Adjust based on result relevance
    if results:
        avg_relevance = sum(r.relevance_score for r in results) / len(results)
        confidence = (confidence + avg_relevance) / 2
    
    return min(confidence, 1.0)