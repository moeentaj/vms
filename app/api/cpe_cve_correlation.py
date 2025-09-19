"""
Complete CPE-CVE Correlation API Router
app/api/cpe_cve_correlation.py

This file provides the complete API router for CPE-CVE correlation functionality.
Replace your existing cpe_cve_correlation.py with this version.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
import logging
import json

from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.models.cve import CVE
from app.models.asset import Asset

logger = logging.getLogger(__name__)
router = APIRouter()

# Pydantic Models
class CPECVEMatchResponse(BaseModel):
    """Response model for CPE-CVE matches"""
    cpe_name: str
    cve_id: str
    match_type: str
    confidence_score: float
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    published_date: Optional[str] = None
    description: Optional[str] = None
    version_affected: Optional[bool] = None
    match_details: Optional[Dict[str, Any]] = None

class VulnerabilityCorrelationRequest(BaseModel):
    """Request model for vulnerability correlation"""
    cpe_name: str
    include_version_range: bool = True
    confidence_threshold: float = Field(0.5, ge=0.0, le=1.0)
    max_results: int = Field(100, ge=1, le=1000)

class AssetVulnerabilityResponse(BaseModel):
    """Response model for asset vulnerability assessment"""
    asset_id: int
    asset_name: str
    total_cves: int
    critical_cves: int
    high_cves: int
    medium_cves: int
    low_cves: int
    risk_score: float
    affected_services: List[Dict[str, Any]]
    recommendations: List[str]
    assessment_timestamp: str
    confidence_level: str

class BulkAssessmentRequest(BaseModel):
    """Request model for bulk vulnerability assessment"""
    asset_ids: Optional[List[int]] = None
    environment_filter: Optional[str] = None
    criticality_filter: Optional[str] = None
    include_inactive: bool = False

# Basic CPE-CVE Correlation Endpoints
@router.post("/correlate-cpe", response_model=List[CPECVEMatchResponse])
async def correlate_cpe_to_cves(
    request: VulnerabilityCorrelationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Find CVEs that affect a specific CPE"""
    try:
        # Import here to avoid circular dependencies
        from app.services.cpe_cve_correlation import CPECVECorrelationEngine
        
        engine = CPECVECorrelationEngine(db)
        matches = await engine.correlate_cpe_to_cves(request.cpe_name)
        
        # Filter by confidence threshold and limit results
        filtered_matches = [
            m for m in matches 
            if m.confidence_score >= request.confidence_threshold
        ][:request.max_results]
        
        # Convert to response format
        response_matches = []
        for match in filtered_matches:
            # Get CVE details from database
            cve = db.query(CVE).filter(CVE.cve_id == match.cve_id).first()
            
            response_match = CPECVEMatchResponse(
                cpe_name=match.cpe_name,
                cve_id=match.cve_id,
                match_type=match.match_type,
                confidence_score=match.confidence_score,
                version_affected=match.version_affected,
                match_details=match.match_details
            )
            
            if cve:
                response_match.cvss_score = cve.cvss_score
                response_match.severity = cve.severity
                response_match.published_date = cve.published_date.isoformat() if cve.published_date else None
                response_match.description = cve.description[:200] + "..." if len(cve.description) > 200 else cve.description
            
            response_matches.append(response_match)
        
        return response_matches
        
    except Exception as e:
        logger.error(f"CPE-CVE correlation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Correlation failed: {str(e)}")

@router.get("/cve/{cve_id}/affected-assets")
async def get_cve_affected_assets(
    cve_id: str,
    confidence_threshold: float = Query(0.6, description="Minimum confidence score"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get assets potentially affected by a specific CVE"""
    try:
        # Get CVE details
        cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        # Get assets with CPE references
        assets_with_cpe = db.query(Asset).filter(
            and_(
                Asset.status == 'active',
                or_(
                    Asset.cpe_name.isnot(None),
                    Asset.os_cpe_name.isnot(None),
                    Asset.additional_services.isnot(None)
                )
            )
        ).all()
        
        affected_assets = []
        
        if cve.cpe_entries:
            from app.services.cpe_cve_correlation import CPECVECorrelationEngine
            engine = CPECVECorrelationEngine(db)
            
            for asset in assets_with_cpe:
                try:
                    # Get all CPE references for this asset
                    cpe_references = asset.get_all_cpe_references()
                    asset_matches = []
                    
                    for cpe_ref in cpe_references:
                        if cpe_ref.get('cpe_name'):
                            matches = await engine.correlate_cpe_to_cves(cpe_ref['cpe_name'])
                            cve_matches = [m for m in matches if m.cve_id == cve_id and m.confidence_score >= confidence_threshold]
                            
                            if cve_matches:
                                asset_matches.extend(cve_matches)
                    
                    if asset_matches:
                        best_match = max(asset_matches, key=lambda x: x.confidence_score)
                        affected_assets.append({
                            "asset": {
                                "id": asset.id,
                                "name": asset.name,
                                "asset_type": asset.asset_type,
                                "ip_address": asset.ip_address,
                                "environment": asset.environment,
                                "criticality": asset.criticality,
                                "primary_service": asset.primary_service,
                                "service_vendor": asset.service_vendor
                            },
                            "confidence_score": best_match.confidence_score,
                            "match_type": best_match.match_type,
                            "affected_services": [m.match_details for m in asset_matches if m.match_details]
                        })
                
                except Exception as e:
                    logger.debug(f"Error checking asset {asset.id} for CVE {cve_id}: {e}")
                    continue
        
        # Sort by confidence score
        affected_assets.sort(key=lambda x: x["confidence_score"], reverse=True)
        
        return {
            "cve_id": cve_id,
            "cve_details": {
                "severity": cve.severity,
                "cvss_score": cve.cvss_score,
                "description": cve.description[:300] + "..." if len(cve.description) > 300 else cve.description,
                "published_date": cve.published_date.isoformat() if cve.published_date else None
            },
            "total_potentially_affected": len(affected_assets),
            "high_confidence_matches": len([a for a in affected_assets if a["confidence_score"] >= 0.8]),
            "confidence_threshold": confidence_threshold,
            "affected_assets": affected_assets[:50]  # Limit results
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Enhanced affected assets lookup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Lookup failed: {str(e)}")

# Asset Vulnerability Assessment Endpoints
@router.get("/asset/{asset_id}/assessment", response_model=AssetVulnerabilityResponse)
async def assess_asset_vulnerabilities(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get comprehensive vulnerability assessment for an asset"""
    try:
        from app.services.cpe_cve_correlation import CPECVECorrelationEngine
        
        engine = CPECVECorrelationEngine(db)
        assessment = await engine.assess_asset_vulnerabilities(asset_id)
        
        return AssetVulnerabilityResponse(
            asset_id=assessment.asset_id,
            asset_name=assessment.asset_name,
            total_cves=assessment.total_cves,
            critical_cves=assessment.critical_cves,
            high_cves=assessment.high_cves,
            medium_cves=assessment.medium_cves,
            low_cves=assessment.low_cves,
            risk_score=assessment.risk_score,
            affected_services=assessment.affected_services,
            recommendations=assessment.recommendations,
            assessment_timestamp=assessment.assessment_timestamp.isoformat(),
            confidence_level=assessment.confidence_level
        )
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Asset vulnerability assessment failed: {e}")
        raise HTTPException(status_code=500, detail=f"Assessment failed: {str(e)}")

@router.post("/assets/bulk-assess")
async def bulk_assess_asset_vulnerabilities(
    background_tasks: BackgroundTasks,
    request: BulkAssessmentRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Bulk vulnerability assessment for multiple assets"""
    if current_user.role not in ["admin", "manager"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Apply filters to determine which assets to assess
    asset_query = db.query(Asset)
    
    if request.asset_ids:
        asset_query = asset_query.filter(Asset.id.in_(request.asset_ids))
    
    if request.environment_filter:
        asset_query = asset_query.filter(Asset.environment == request.environment_filter)
    
    if request.criticality_filter:
        asset_query = asset_query.filter(Asset.criticality == request.criticality_filter)
    
    if not request.include_inactive:
        asset_query = asset_query.filter(Asset.status == 'active')
    
    # Only process assets with CPE references
    asset_query = asset_query.filter(
        or_(
            Asset.cpe_name.isnot(None),
            Asset.os_cpe_name.isnot(None),
            Asset.additional_services.isnot(None)
        )
    )
    
    assets = asset_query.all()
    
    async def run_bulk_assessment():
        try:
            from app.services.cpe_cve_correlation import CPECVECorrelationEngine
            
            engine = CPECVECorrelationEngine(db)
            stats = await engine.bulk_correlate_assets([asset.id for asset in assets])
            
            logger.info(f"Bulk asset assessment completed: {stats}")
        except Exception as e:
            logger.error(f"Bulk asset assessment failed: {e}")
    
    background_tasks.add_task(run_bulk_assessment)
    
    return {
        "message": f"Bulk vulnerability assessment started for {len(assets)} assets",
        "assets_queued": len(assets),
        "filters_applied": {
            "environment": request.environment_filter,
            "criticality": request.criticality_filter,
            "include_inactive": request.include_inactive
        }
    }

# Search and Analysis Endpoints
@router.get("/vulnerabilities/search")
async def search_vulnerabilities_by_criteria(
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    product: Optional[str] = Query(None, description="Filter by product"),
    version: Optional[str] = Query(None, description="Filter by version"),
    severity: Optional[str] = Query(None, description="Filter by CVE severity"),
    confidence_min: float = Query(0.7, description="Minimum confidence score"),
    limit: int = Query(50, description="Maximum results"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Search for vulnerabilities based on software criteria"""
    try:
        # Build search criteria
        search_components = []
        if vendor:
            search_components.append(vendor.lower())
        if product:
            search_components.append(product.lower())
        if version:
            search_components.append(version.lower())
        
        if not search_components:
            raise HTTPException(status_code=400, detail="At least one search criterion required")
        
        # Find CVEs matching the criteria
        query = db.query(CVE)
        
        # Search in description and affected products
        search_conditions = []
        for component in search_components:
            search_conditions.extend([
                CVE.description.ilike(f'%{component}%'),
                CVE.affected_products.ilike(f'%{component}%') if hasattr(CVE, 'affected_products') else None
            ])
        
        # Remove None conditions
        search_conditions = [c for c in search_conditions if c is not None]
        
        if search_conditions:
            query = query.filter(or_(*search_conditions))
        
        if severity:
            query = query.filter(CVE.severity == severity.upper())
        
        # Filter by correlation confidence if available
        if confidence_min > 0 and hasattr(CVE, 'correlation_confidence'):
            query = query.filter(CVE.correlation_confidence >= confidence_min)
        
        cves = query.limit(limit).all()
        
        results = []
        for cve in cves:
            result = {
                "cve_id": cve.cve_id,
                "description": cve.description[:200] + "..." if len(cve.description) > 200 else cve.description,
                "cvss_score": cve.cvss_score,
                "severity": cve.severity,
                "published_date": cve.published_date.isoformat() if cve.published_date else None,
                "correlation_confidence": getattr(cve, 'correlation_confidence', None),
                "affected_products": getattr(cve, 'affected_products', None)
            }
            results.append(result)
        
        return {
            "search_criteria": {
                "vendor": vendor,
                "product": product,
                "version": version,
                "severity": severity,
                "confidence_min": confidence_min
            },
            "total_results": len(results),
            "vulnerabilities": results
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Vulnerability search failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

# Statistics and Dashboard Endpoints
@router.get("/stats/correlation-overview")
async def get_correlation_statistics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get comprehensive correlation statistics"""
    try:
        # Basic counts
        total_cves = db.query(CVE).count()
        total_assets = db.query(Asset).count()
        
        # Assets with CPE references
        assets_with_cpe = db.query(Asset).filter(
            or_(
                Asset.cpe_name.isnot(None),
                Asset.os_cpe_name.isnot(None),
                Asset.additional_services.isnot(None)
            )
        ).count()
        
        # CVEs with correlation data
        correlated_cves = 0
        if hasattr(CVE, 'correlation_confidence'):
            correlated_cves = db.query(CVE).filter(CVE.correlation_confidence > 0).count()
        
        # Environment breakdown
        env_stats = db.query(Asset.environment, db.func.count(Asset.id)).group_by(Asset.environment).all()
        environment_breakdown = {env: count for env, count in env_stats}
        
        # Criticality breakdown
        crit_stats = db.query(Asset.criticality, db.func.count(Asset.id)).group_by(Asset.criticality).all()
        criticality_breakdown = {crit: count for crit, count in crit_stats}
        
        return {
            "overview": {
                "total_cves": total_cves,
                "total_assets": total_assets,
                "assets_with_cpe": assets_with_cpe,
                "cpe_coverage": round((assets_with_cpe / total_assets * 100) if total_assets > 0 else 0, 2),
                "correlated_cves": correlated_cves,
                "correlation_coverage": round((correlated_cves / total_cves * 100) if total_cves > 0 else 0, 2)
            },
            "asset_distribution": {
                "by_environment": environment_breakdown,
                "by_criticality": criticality_breakdown
            },
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get correlation statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Statistics failed: {str(e)}")

# Testing Endpoints
@router.get("/test/cpe-parsing")
async def test_cpe_parsing(
    cpe_name: str = Query(..., description="CPE name to parse"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Test CPE name parsing functionality"""
    try:
        from app.services.cpe_cve_correlation import CPECVECorrelationEngine
        
        engine = CPECVECorrelationEngine(db)
        parsed_cpe = engine.parse_cpe_name(cpe_name)
        
        return {
            "input_cpe": cpe_name,
            "parsed_result": parsed_cpe,
            "is_valid": parsed_cpe is not None,
            "test_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"CPE parsing test failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")

@router.get("/test/version-comparison")
async def test_version_comparison(
    version1: str = Query(..., description="First version"),
    version2: str = Query(..., description="Second version"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Test version comparison functionality"""
    try:
        from app.services.cpe_cve_correlation import CPECVECorrelationEngine
        
        engine = CPECVECorrelationEngine(db)
        comparison_result = engine.compare_versions(version1, version2)
        
        result_text = "equal"
        if comparison_result < 0:
            result_text = f"{version1} is older than {version2}"
        elif comparison_result > 0:
            result_text = f"{version1} is newer than {version2}"
        else:
            result_text = f"{version1} is equal to {version2}"
        
        return {
            "version1": version1,
            "version2": version2,
            "comparison_result": comparison_result,
            "result_description": result_text,
            "test_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Version comparison test failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")