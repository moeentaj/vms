"""
Enhanced CPE to CVE API Endpoints
Extends your existing API with comprehensive CPE-CVE correlation functionality
app/api/cpe_cve_correlation.py
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from app.models.cve import CVE
from app.models.asset import Asset
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import logging
import time
from datetime import datetime, timedelta

from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User
from app.services.cpe_cve_correlation import (
    CPECVECorrelationEngine,
    AssetVulnerabilityAssessment,
    correlate_asset_vulnerabilities,
    get_cpe_vulnerabilities,
    bulk_assess_infrastructure
)

logger = logging.getLogger(__name__)
router = APIRouter()

# Enhanced Pydantic Models
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
    version_affected: Optional[str] = None
    match_details: Optional[Dict[str, Any]] = None

class CPEVulnerabilitySummaryResponse(BaseModel):
    """Response model for CPE vulnerability summary"""
    cpe_name: str
    total_cves: int
    severity_breakdown: Dict[str, int]
    confidence_levels: Dict[str, int]
    latest_cve: Optional[str] = None
    latest_cve_date: Optional[str] = None
    high_confidence_matches: int
    recommendations: List[str]
    risk_score: float = 0.0
    
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
    last_assessed: str
    correlation_confidence: float

class BulkAssessmentRequest(BaseModel):
    """Request model for bulk vulnerability assessment"""
    asset_ids: Optional[List[int]] = None
    environment_filter: Optional[str] = None
    criticality_filter: Optional[str] = None
    include_inactive: bool = False

class VulnerabilityCorrelationRequest(BaseModel):
    """Request model for vulnerability correlation"""
    cpe_name: str
    include_version_range: bool = True
    confidence_threshold: float = Field(0.5, ge=0.0, le=1.0)
    max_results: int = Field(100, ge=1, le=1000)

# CPE to CVE Correlation Endpoints

@router.post("/correlate-cpe", response_model=List[CPECVEMatchResponse])
async def correlate_cpe_to_cves(
    request: VulnerabilityCorrelationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Find CVEs that affect a specific CPE"""
    try:
        engine = CPECVECorrelationEngine(db)
        matches = await engine.correlate_cpe_to_cves(
            request.cpe_name, 
            request.include_version_range
        )
        
        # Filter by confidence threshold and limit results
        filtered_matches = [
            m for m in matches 
            if m.confidence_score >= request.confidence_threshold
        ][:request.max_results]
        
        # Enrich with CVE data
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
                response_match.cvss_score = cve.get_primary_cvss_score()
                response_match.severity = cve.severity
                response_match.published_date = cve.published_date.isoformat() if cve.published_date else None
                response_match.description = cve.description[:200] + "..." if len(cve.description) > 200 else cve.description
            
            response_matches.append(response_match)
        
        return response_matches
        
    except Exception as e:
        logger.error(f"CPE-CVE correlation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Correlation failed: {str(e)}")

@router.get("/cpe/{cpe_name:path}/vulnerabilities", response_model=CPEVulnerabilitySummaryResponse)
async def get_cpe_vulnerability_summary(
    cpe_name: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get comprehensive vulnerability summary for a CPE"""
    try:
        summary = await get_cpe_vulnerabilities(db, cpe_name)
        
        # Calculate risk score based on severity distribution
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        risk_score = sum(
            count * severity_weights.get(severity, 0) 
            for severity, count in summary['severity_breakdown'].items()
        )
        
        return CPEVulnerabilitySummaryResponse(
            risk_score=min(risk_score, 100.0),  # Cap at 100
            **summary
        )
        
    except Exception as e:
        logger.error(f"Failed to get CPE vulnerability summary: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get vulnerability summary: {str(e)}")

# Asset Vulnerability Assessment Endpoints

@router.get("/assets/{asset_id}/vulnerabilities", response_model=AssetVulnerabilityResponse)
async def assess_asset_vulnerabilities(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get comprehensive vulnerability assessment for an asset"""
    try:
        assessment = await correlate_asset_vulnerabilities(db, asset_id)
        
        # Update asset record with assessment results
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset:
            asset.vulnerability_score = assessment.risk_score
            asset.last_vulnerability_scan = datetime.now()
            db.commit()
        
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
            last_assessed=datetime.now().isoformat(),
            correlation_confidence=assessment.risk_score / 100.0  # Normalize to 0-1
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
    asset_ids_to_process = [asset.id for asset in assets]
    
    # Start background assessment
    background_tasks.add_task(
        run_bulk_assessment_task,
        db,
        asset_ids_to_process,
        current_user.username
    )
    
    return {
        "message": f"Bulk vulnerability assessment started for {len(asset_ids_to_process)} assets",
        "assets_queued": len(asset_ids_to_process),
        "filters_applied": {
            "environment": request.environment_filter,
            "criticality": request.criticality_filter,
            "include_inactive": request.include_inactive
        }
    }

# Vulnerability Search and Analysis Endpoints

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
        # Build CPE-like search pattern
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
                CVE.affected_products.ilike(f'%{component}%'),
                CVE.cpe_entries.ilike(f'%{component}%')
            ])
        
        if search_conditions:
            query = query.filter(or_(*search_conditions))
        
        if severity:
            query = query.filter(CVE.severity == severity.upper())
        
        # Filter by correlation confidence if available
        if confidence_min > 0:
            query = query.filter(CVE.correlation_confidence >= confidence_min)
        
        cves = query.limit(limit).all()
        
        results = []
        for cve in cves:
            result = {
                "cve_id": cve.cve_id,
                "description": cve.description[:200] + "..." if len(cve.description) > 200 else cve.description,
                "cvss_score": cve.get_primary_cvss_score(),
                "severity": cve.severity,
                "published_date": cve.published_date.isoformat() if cve.published_date else None,
                "correlation_confidence": cve.correlation_confidence,
                "affected_products": cve.affected_products,
                "ai_risk_score": cve.ai_risk_score
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

@router.get("/assets/{asset_id}/cpe-mappings")
async def get_asset_cpe_mappings(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all CPE mappings for an asset with vulnerability counts"""
    try:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        cpe_references = asset.get_all_cpe_references()
        cpe_mappings = []
        
        for cpe_ref in cpe_references:
            if cpe_ref['cpe_name']:
                # Get vulnerability summary for this CPE
                vuln_summary = await get_cpe_vulnerabilities(db, cpe_ref['cpe_name'])
                
                mapping = {
                    "service_type": cpe_ref['type'],
                    "service_name": cpe_ref['product'],
                    "vendor": cpe_ref.get('vendor'),
                    "cpe_name": cpe_ref['cpe_name'],
                    "vulnerability_count": vuln_summary['total_cves'],
                    "severity_breakdown": vuln_summary['severity_breakdown'],
                    "high_confidence_matches": vuln_summary['high_confidence_matches'],
                    "latest_cve": vuln_summary['latest_cve'],
                    "risk_level": "high" if vuln_summary.get('critical', 0) > 0 else 
                                 "medium" if vuln_summary.get('high', 0) > 0 else "low"
                }
                cpe_mappings.append(mapping)
        
        return {
            "asset_id": asset.id,
            "asset_name": asset.name,
            "cpe_mappings": cpe_mappings,
            "total_cpe_references": len(cpe_mappings),
            "last_updated": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get CPE mappings: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get CPE mappings: {str(e)}")

# Dashboard and Statistics Endpoints

@router.get("/dashboard/vulnerability-overview")
async def get_vulnerability_dashboard_data(
    environment: Optional[str] = Query(None, description="Filter by environment"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get vulnerability overview data for dashboard"""
    try:
        # Base queries
        asset_query = db.query(Asset).filter(Asset.status == 'active')
        cve_query = db.query(CVE)
        
        if environment:
            asset_query = asset_query.filter(Asset.environment == environment)
        
        # Asset statistics
        total_assets = asset_query.count()
        assets_with_cpe = asset_query.filter(
            or_(
                Asset.cpe_name.isnot(None),
                Asset.os_cpe_name.isnot(None),
                Asset.additional_services.isnot(None)
            )
        ).count()
        
        # Vulnerability statistics
        total_cves = cve_query.count()
        recent_cves = cve_query.filter(
            CVE.published_date >= datetime.now() - timedelta(days=30)
        ).count()
        
        # Severity breakdown
        severity_breakdown = {
            'critical': cve_query.filter(CVE.severity == 'CRITICAL').count(),
            'high': cve_query.filter(CVE.severity == 'HIGH').count(),
            'medium': cve_query.filter(CVE.severity == 'MEDIUM').count(),
            'low': cve_query.filter(CVE.severity == 'LOW').count()
        }
        
        # Risk assessment by environment
        risk_by_env = {}
        if not environment:
            for env in ['production', 'staging', 'development', 'test']:
                env_assets = db.query(Asset).filter(
                    and_(Asset.environment == env, Asset.status == 'active')
                ).all()
                
                total_risk = sum(asset.vulnerability_score or 0 for asset in env_assets)
                asset_count = len(env_assets)
                avg_risk = total_risk / asset_count if asset_count > 0 else 0
                
                risk_by_env[env] = {
                    'asset_count': asset_count,
                    'average_risk_score': round(avg_risk, 2),
                    'high_risk_assets': len([a for a in env_assets if (a.vulnerability_score or 0) > 70])
                }
        
        # Top vulnerable assets
        high_risk_assets = asset_query.filter(
            Asset.vulnerability_score > 50
        ).order_by(Asset.vulnerability_score.desc()).limit(10).all()
        
        vulnerable_assets = []
        for asset in high_risk_assets:
            vulnerable_assets.append({
                'id': asset.id,
                'name': asset.name,
                'environment': asset.environment,
                'criticality': asset.criticality,
                'vulnerability_score': asset.vulnerability_score,
                'last_scan': asset.last_vulnerability_scan.isoformat() if asset.last_vulnerability_scan else None
            })
        
        return {
            "overview": {
                "total_assets": total_assets,
                "assets_with_cpe": assets_with_cpe,
                "coverage_percentage": round((assets_with_cpe / total_assets * 100) if total_assets > 0 else 0, 1),
                "total_cves": total_cves,
                "recent_cves": recent_cves
            },
            "severity_breakdown": severity_breakdown,
            "risk_by_environment": risk_by_env,
            "top_vulnerable_assets": vulnerable_assets,
            "last_updated": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Dashboard data retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")

# Background task functions
async def run_bulk_assessment_task(db: Session, asset_ids: List[int], username: str):
    """Background task for bulk vulnerability assessment"""
    try:
        logger.info(f"Starting bulk assessment for {len(asset_ids)} assets by {username}")
        stats = await bulk_assess_infrastructure(db, asset_ids)
        logger.info(f"Bulk assessment completed: {stats}")
        
        # Could add notification logic here
        
    except Exception as e:
        logger.error(f"Bulk assessment task failed: {e}")

# Utility endpoints for integration with your existing frontend

@router.post("/assets/{asset_id}/trigger-assessment")
async def trigger_single_asset_assessment(
    asset_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Trigger vulnerability assessment for a single asset (for use in asset management UI)"""
    try:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        # Quick assessment that can be called from your existing UI
        background_tasks.add_task(assess_single_asset_task, db, asset_id)
        
        return {
            "message": f"Vulnerability assessment started for asset: {asset.name}",
            "asset_id": asset_id,
            "estimated_completion": "2-5 minutes"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to trigger assessment: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to trigger assessment: {str(e)}")

async def assess_single_asset_task(db: Session, asset_id: int):
    """Background task for single asset assessment"""
    try:
        assessment = await correlate_asset_vulnerabilities(db, asset_id)
        
        # Update asset record
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset:
            asset.vulnerability_score = assessment.risk_score
            asset.last_vulnerability_scan = datetime.now()
            db.commit()
            
        logger.info(f"Assessment completed for asset {asset_id}: {assessment.total_cves} CVEs found")
        
    except Exception as e:
        logger.error(f"Single asset assessment task failed for asset {asset_id}: {e}")

# Integration endpoint for your existing CVE management
@router.get("/cves/{cve_id}/affected-assets-enhanced")
async def get_enhanced_affected_assets(
    cve_id: str,
    confidence_threshold: float = Query(0.7, ge=0.0, le=1.0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Enhanced version of your existing affected assets endpoint with CPE correlation"""
    try:
        cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if not cve:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
        
        # Get all assets with CPE references
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
        engine = CPECVECorrelationEngine(db)
        
        for asset in assets_with_cpe:
            cpe_references = asset.get_all_cpe_references()
            asset_matches = []
            
            for cpe_ref in cpe_references:
                if cpe_ref['cpe_name']:
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
                        "criticality": asset.criticality
                    },
                    "confidence_score": best_match.confidence_score,
                    "match_type": best_match.match_type,
                    "affected_services": [m.match_details for m in asset_matches if m.match_details]
                })
        
        # Sort by confidence score
        affected_assets.sort(key=lambda x: x["confidence_score"], reverse=True)
        
        return {
            "cve_id": cve_id,
            "total_potentially_affected": len(affected_assets),
            "high_confidence_matches": len([a for a in affected_assets if a["confidence_score"] >= 0.8]),
            "confidence_threshold": confidence_threshold,
            "affected_assets": affected_assets
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Enhanced affected assets lookup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Lookup failed: {str(e)}")