from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api import auth, cves, assets, assignments, recommendations, cpe_cve_correlation
from app.api import enhanced_cpe_lookup
from app.api.cpe_lookup import router as cpe_lookup_router
import logging

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

app = FastAPI(
    title="Vulnerability Management System",
    description="AI-powered vulnerability management with cost-optimized local AI",
    version="1.0.0",
    debug=settings.DEBUG
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["authentication"])
app.include_router(cves.router, prefix="/api/v1/cves", tags=["cves"])
app.include_router(assets.router, prefix="/api/v1/assets", tags=["assets"])
app.include_router(assignments.router, prefix="/api/v1/assignments", tags=["assignments"])
app.include_router(recommendations.router, prefix="/api/v1/recommendations", tags=["recommendations"])
app.include_router(cpe_lookup_router, prefix="/api/v1/cpe-lookup", tags=["CPE Lookup"])
app.include_router(cpe_cve_correlation.router, prefix="/api/v1/cpe-cve-correlation", tags=["cpe-cve-correlation"])
app.include_router(enhanced_cpe_lookup.router, prefix="/api/v1/enhanced-cpe", tags=["Enhanced CPE"])

@app.get("/")
async def root():
    return {"message": "Vulnerability Management System API", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=settings.DEBUG)