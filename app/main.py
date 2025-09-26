"""
Enhanced Main Application with CPE Dictionary 2.0 and CPE Match 2.0 Integration
app/main.py

Updated main application file with new enhanced CPE routes and improved configuration.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import time
from typing import Dict, Any
import os

from app.core.config import settings, validate_environment
from app.api import (
    auth, 
    cves, 
    assets, 
    assignments, 
    recommendations, 
    cpe_cve_correlation
)
from app.api import enhanced_cpe_lookup
from app.api.cpe_lookup import router as cpe_lookup_router

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log') if not settings.DEBUG else logging.NullHandler()
    ]
)

logger = logging.getLogger(__name__)

# Startup/shutdown event handler
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown events"""
    # Startup
    logger.info(f"Starting {settings.APP_NAME} v1.0.0")
    logger.info(f"Environment: {'Development' if settings.DEBUG else 'Production'}")
    
    # Validate environment configuration
    config_issues = validate_environment()
    if config_issues:
        logger.warning("Configuration issues found:")
        for issue in config_issues:
            logger.warning(f"  - {issue}")
    
    # Initialize cache directories
    from app.core.config import get_cpe_cache_path, get_cve_cache_path
    import os
    
    os.makedirs(get_cpe_cache_path(), exist_ok=True)
    os.makedirs(get_cve_cache_path(), exist_ok=True)
    logger.info("Cache directories initialized")
    
    # Initialize background tasks if enabled
    if settings.ENABLE_BACKGROUND_INGESTION:
        logger.info("Background ingestion enabled - tasks will run automatically")
    
    yield
    
    # Shutdown
    logger.info(f"Shutting down {settings.APP_NAME}")

# Create FastAPI application
app = FastAPI(
    title="Enhanced Vulnerability Management System",
    description="AI-powered vulnerability management with CPE Dictionary 2.0 and CPE Match 2.0 integration",
    version="2.0.0",
    debug=settings.DEBUG,
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None
)

# Add middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unhandled errors"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    if settings.DEBUG:
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "detail": str(exc),
                "type": type(exc).__name__
            }
        )
    else:
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error"}
        )

# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request, call_next):
    """Add response time header"""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

# Include routers with versioning
api_v1_prefix = "/api/v1"

# Core API routes
app.include_router(
    auth.router, 
    prefix=f"{api_v1_prefix}/auth", 
    tags=["Authentication"]
)

app.include_router(
    cves.router, 
    prefix=f"{api_v1_prefix}/cves", 
    tags=["CVE Management"]
)

app.include_router(
    assets.router, 
    prefix=f"{api_v1_prefix}/assets", 
    tags=["Asset Management"]
)

app.include_router(
    assignments.router, 
    prefix=f"{api_v1_prefix}/assignments", 
    tags=["Vulnerability Assignments"]
)

app.include_router(
    recommendations.router, 
    prefix=f"{api_v1_prefix}/recommendations", 
    tags=["Recommendations"]
)

# CPE and Correlation routes
app.include_router(
    cpe_lookup_router, 
    prefix=f"{api_v1_prefix}/cpe-lookup", 
    tags=["CPE Lookup (Legacy)"]
)

app.include_router(
    enhanced_cpe_lookup.router, 
    prefix=f"{api_v1_prefix}/enhanced-cpe", 
    tags=["Enhanced CPE Dictionary 2.0"]
)

app.include_router(
    cpe_cve_correlation.router, 
    prefix=f"{api_v1_prefix}/cpe-cve-correlation", 
    tags=["CVE-CPE Correlation"]
)

# Root endpoints
@app.get("/")
async def root():
    """Root endpoint with system information"""
    return {
        "message": "Enhanced Vulnerability Management System API",
        "version": "2.0.0",
        "features": {
            "cpe_dictionary_2_0": True,
            "cpe_match_2_0": True,
            "enhanced_correlation": True,
            "ai_enhancement": settings.ENABLE_AI_ENHANCEMENT,
            "background_ingestion": settings.ENABLE_BACKGROUND_INGESTION,
            "asset_correlation": settings.ASSET_CORRELATION_ENABLED,
            "redis_cache": settings.ENABLE_REDIS_CACHE,
            "metrics": settings.ENABLE_METRICS
        },
        "documentation": {
            "swagger_ui": "/docs" if settings.DEBUG else "disabled",
            "redoc": "/redoc" if settings.DEBUG else "disabled"
        }
    }

@app.get("/health")
async def health_check():
    """Comprehensive health check endpoint"""
    start_time = time.time()
    
    health_status = {
        "status": "healthy",
        "timestamp": time.time(),
        "version": "2.0.0",
        "environment": "development" if settings.DEBUG else "production",
        "checks": {}
    }
    
    try:
        # Database check
        from app.core.database import get_db
        from sqlalchemy import text
        
        db = next(get_db())
        try:
            db.execute(text("SELECT 1"))
            health_status["checks"]["database"] = {"status": "healthy", "response_time_ms": 0}
        except Exception as e:
            health_status["checks"]["database"] = {
                "status": "unhealthy", 
                "error": str(e),
                "response_time_ms": 0
            }
            health_status["status"] = "degraded"
        finally:
            db.close()
        
        # CPE cache check
        from app.core.config import get_cpe_cache_path
        import os
        
        cpe_cache_exists = os.path.exists(get_cpe_cache_path("enhanced_cpe_products.json"))
        health_status["checks"]["cpe_cache"] = {
            "status": "healthy" if cpe_cache_exists else "warning",
            "cache_available": cpe_cache_exists,
            "cache_path": get_cpe_cache_path()
        }
        
        # CVE cache check
        from app.core.config import get_cve_cache_path
        
        cve_cache_dir_exists = os.path.exists(get_cve_cache_path())
        health_status["checks"]["cve_cache"] = {
            "status": "healthy" if cve_cache_dir_exists else "warning",
            "cache_dir_exists": cve_cache_dir_exists,
            "cache_path": get_cve_cache_path()
        }
        
        # Configuration check
        config_issues = validate_environment()
        health_status["checks"]["configuration"] = {
            "status": "healthy" if not config_issues else "warning",
            "issues": config_issues
        }
        
    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["error"] = str(e)
        logger.error(f"Health check failed: {e}")
    
    # Overall response time
    health_status["response_time_ms"] = int((time.time() - start_time) * 1000)
    
    # Set appropriate HTTP status code
    status_code = 200
    if health_status["status"] == "degraded":
        status_code = 200  # Still functional
    elif health_status["status"] == "unhealthy":
        status_code = 503  # Service unavailable
    
    return JSONResponse(content=health_status, status_code=status_code)

@app.get("/version")
async def version_info():
    """Detailed version information"""
    return {
        "application": {
            "name": settings.APP_NAME,
            "version": "2.0.0",
            "build": "enhanced-cpe-integration",
            "environment": "development" if settings.DEBUG else "production"
        },
        "api": {
            "version": "v1",
            "endpoints": [
                "/api/v1/auth",
                "/api/v1/cves",
                "/api/v1/assets",
                "/api/v1/assignments",
                "/api/v1/recommendations",
                "/api/v1/cpe-lookup",
                "/api/v1/enhanced-cpe",
                "/api/v1/cpe-cve-correlation"
            ]
        },
        "features": {
            "cpe_dictionary": "2.0",
            "cpe_match": "2.0",
            "nvd_api": "2.0",
            "enhanced_correlation": True,
            "background_processing": settings.ENABLE_BACKGROUND_INGESTION,
            "caching": "file-based" + (" + redis" if settings.ENABLE_REDIS_CACHE else ""),
            "monitoring": settings.ENABLE_METRICS
        },
        "data_sources": {
            "cpe_dictionary": settings.CPE_DICTIONARY_URL,
            "cpe_match": settings.CPE_MATCH_URL,
            "nvd_cve_feeds": settings.CVE_DATA_FEED_BASE_URL
        }
    }

@app.get("/status")
async def system_status():
    """System status endpoint for monitoring"""
    try:
        # Get system statistics
        from app.core.database import get_db
        from app.models.cve import CVE
        from app.models.asset import Asset
        from sqlalchemy import func
        
        db = next(get_db())
        try:
            # Database statistics
            cve_count = db.query(func.count(CVE.id)).scalar()
            asset_count = db.query(func.count(Asset.id)).scalar()
            
            # Recent activity
            from datetime import datetime, timedelta
            recent_date = datetime.now() - timedelta(days=7)
            recent_cves = db.query(func.count(CVE.id)).filter(
                CVE.published_date >= recent_date
            ).scalar()
            
        finally:
            db.close()
        
        # CPE status
        from app.services.enhanced_cpe_dictionary import EnhancedCPEDictionaryManager
        
        cpe_manager = EnhancedCPEDictionaryManager(db)
        cpe_status = cpe_manager.get_status()
        
        return {
            "system": {
                "status": "operational",
                "uptime_seconds": time.time() - getattr(app.state, 'start_time', time.time()),
                "version": "2.0.0"
            },
            "database": {
                "total_cves": cve_count,
                "total_assets": asset_count,
                "recent_cves_7_days": recent_cves
            },
            "cpe_system": {
                "has_data": cpe_status.get('has_data', False),
                "total_products": cpe_status.get('total_products', 0),
                "total_matches": cpe_status.get('total_matches', 0),
                "last_updated": cpe_status.get('last_updated'),
                "search_indices_built": cpe_status.get('search_indices_built', False)
            },
            "configuration": {
                "debug_mode": settings.DEBUG,
                "background_ingestion": settings.ENABLE_BACKGROUND_INGESTION,
                "asset_correlation": settings.ASSET_CORRELATION_ENABLED,
                "redis_cache": settings.ENABLE_REDIS_CACHE,
                "nist_api_key_configured": bool(settings.NVD_API_KEY)
            }
        }
        
    except Exception as e:
        logger.error(f"Status check failed: {e}")
        return JSONResponse(
            content={
                "system": {"status": "error", "error": str(e)},
                "timestamp": time.time()
            },
            status_code=500
        )

@app.get("/metrics")
async def metrics_endpoint():
    """Basic metrics endpoint (Prometheus format if metrics enabled)"""
    if not settings.ENABLE_METRICS:
        raise HTTPException(status_code=404, detail="Metrics not enabled")
    
    try:
        from app.core.database import get_db
        from app.models.cve import CVE
        from app.models.asset import Asset
        from sqlalchemy import func
        
        db = next(get_db())
        try:
            metrics_data = {
                "cves_total": db.query(func.count(CVE.id)).scalar(),
                "assets_total": db.query(func.count(Asset.id)).scalar(),
                "cves_critical": db.query(func.count(CVE.id)).filter(
                    CVE.severity == 'critical'
                ).scalar(),
                "cves_high": db.query(func.count(CVE.id)).filter(
                    CVE.severity == 'high'
                ).scalar()
            }
        finally:
            db.close()
        
        # Format as Prometheus metrics
        prometheus_format = f"""# HELP cves_total Total number of CVEs
# TYPE cves_total gauge
cves_total {metrics_data['cves_total']}

# HELP assets_total Total number of assets
# TYPE assets_total gauge
assets_total {metrics_data['assets_total']}

# HELP cves_critical Number of critical CVEs
# TYPE cves_critical gauge
cves_critical {metrics_data['cves_critical']}

# HELP cves_high Number of high severity CVEs
# TYPE cves_high gauge
cves_high {metrics_data['cves_high']}

# HELP app_info Application information
# TYPE app_info gauge
app_info{{version="2.0.0",environment="{'development' if settings.DEBUG else 'production'}"}} 1
"""
        
        return JSONResponse(
            content=prometheus_format,
            media_type="text/plain; version=0.0.4"
        )
        
    except Exception as e:
        logger.error(f"Metrics endpoint failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate metrics")

# Store application start time for uptime calculation
@app.on_event("startup")
async def store_start_time():
    app.state.start_time = time.time()

# Development helper endpoints (only in debug mode)
if settings.DEBUG:
    @app.get("/debug/config")
    async def debug_config():
        """Debug endpoint to view configuration (development only)"""
        return {
            "settings": {
                "app_name": settings.APP_NAME,
                "debug": settings.DEBUG,
                "log_level": settings.LOG_LEVEL,
                "cpe_cache_dir": settings.CPE_CACHE_DIR,
                "cve_cache_dir": settings.CVE_CACHE_DIR,
                "database_url": settings.DATABASE_URL.replace(
                    settings.DATABASE_URL.split('@')[0].split('//')[1] + '@', 
                    '***:***@'
                ) if '@' in settings.DATABASE_URL else 'sqlite',
                "nist_api_key_configured": bool(settings.NVD_API_KEY),
                "features": {
                    "background_ingestion": settings.ENABLE_BACKGROUND_INGESTION,
                    "asset_correlation": settings.ASSET_CORRELATION_ENABLED,
                    "redis_cache": settings.ENABLE_REDIS_CACHE,
                    "metrics": settings.ENABLE_METRICS
                }
            },
            "validation_issues": validate_environment()
        }
    
    @app.post("/debug/clear-cache")
    async def debug_clear_cache():
        """Debug endpoint to clear all caches (development only)"""
        try:
            import shutil
            from app.core.config import get_cpe_cache_path, get_cve_cache_path
            
            removed_paths = []
            
            # Clear CPE cache
            cpe_cache = get_cpe_cache_path()
            if os.path.exists(cpe_cache):
                shutil.rmtree(cpe_cache)
                os.makedirs(cpe_cache, exist_ok=True)
                removed_paths.append(cpe_cache)
            
            # Clear CVE cache
            cve_cache = get_cve_cache_path()
            if os.path.exists(cve_cache):
                shutil.rmtree(cve_cache)
                os.makedirs(cve_cache, exist_ok=True)
                removed_paths.append(cve_cache)
            
            return {
                "message": "Cache cleared successfully",
                "cleared_paths": removed_paths
            }
            
        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to clear cache: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    
    # Configure uvicorn based on environment
    uvicorn_config = {
        "app": "app.main:app",
        "host": "0.0.0.0",
        "port": 8000,
        "reload": settings.DEBUG,
        "log_level": settings.LOG_LEVEL.lower(),
        "access_log": settings.DEBUG,
        "workers": 1 if settings.DEBUG else 4
    }
    
    if not settings.DEBUG:
        # Production optimizations
        uvicorn_config.update({
            "loop": "uvloop",
            "http": "httptools"
        })
    
    logger.info(f"Starting server with config: {uvicorn_config}")
    uvicorn.run(**uvicorn_config)