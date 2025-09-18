"""
Updated CVE API endpoints for Asset-Based Architecture
app/api/cves.py
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, or_, func
from typing import List, Optional, Dict, Any
from app.core.database import get_db
from app.models.cve import CVE
from app.models.asset import Asset  # Changed from service imports
from app.api.auth import get_current_user
from app.models.user import User
from pydantic import BaseModel, field_validator
from datetime import datetime
import logging
import json

logger = logging.getLogger(__name__)
router = APIRouter()

# Updated Response Models for Asset-Based Architecture
class AssetResponse(BaseModel):
    """Asset information for CVE correlations"""
    id: int
    name: str
    asset_type: str
    ip_address: Optional[str]
    hostname: Optional[str]
    primary_service: Optional[str]
    service_vendor: Optional[str]
    service_version: Optional[str]
    environment: str
    criticality: str
    location: Optional[str]
    owner_team: Optional[str]
    
    class Config:
        from_attributes = True

class AssetCorrelationResponse(BaseModel):
    """Asset correlation with CVE"""
    id: int
    asset: AssetResponse
    confidence_score: float
    correlation_method: str
    status: str
    impact_score: Optional[float]
    correlation_details: Optional[Dict[str, Any]]
    affected_services: Optional[List[str]] = None  # Services on this asset that are affected
    
    class Config:
        from_attributes = True

class CVEResponse(BaseModel):
    id: int
    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: Optional[str]
    ai_risk_score: Optional[float]
    ai_summary: Optional[str]
    published_date: Optional[str]
    mitigation_suggestions: Optional[str] = None
    detection_methods: Optional[str] = None
    upgrade_paths: Optional[str] = None
    
    # Enhanced fields for asset correlation
    affected_products: Optional[Dict[str, Any]] = None
    cpe_entries: Optional[List[str]] = None
    correlation_confidence: Optional[float] = None
    affects_assets: Optional[List[int]] = None  # Changed from service types
    
    # Related asset correlations
    asset_correlations: Optional[List[AssetCorrelationResponse]] = None
    
    @field_validator('published_date', mode='before')
    @classmethod
    def convert_datetime_to_string(cls, v):
        if isinstance(v, datetime):
            return v.isoformat()
        return v
    
    class Config:
        from_attributes = True

# Request Models
class CorrelationRequest(BaseModel):
    confidence_threshold: float = 0.7
    include_low_confidence: bool = False

class CPEMappingRequest(BaseModel):
    """Mapping CVE CPE entries to asset services"""
    cpe_name: str
    asset_service_pattern: str  # Pattern to match against asset primary_service
    vendor_pattern: Optional[str] = None
    confidence: float = 1.0
    notes: Optional[str] = None

# Statistics and reporting
@router.get("/correlation-stats")
async def get_correlation_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get correlation statistics for asset-based architecture"""
    try:
        # Check if we have any CVEs first
        total_cves = db.query(CVE).count()
        
        if total_cves == 0:
            return {
                "total_cves": 0,
                "correlated_cves": 0,
                "correlation_coverage": 0,
                "affected_assets": 0,
                "critical_assets_affected": 0,
                "environments_affected": [],
                "message": "No CVEs found in database"
            }
        
        # Count correlated CVEs (those with correlation confidence > 0)
        correlated_cves = db.query(CVE).filter(CVE.correlation_confidence > 0).count()
        
        # Get asset correlation statistics
        total_assets = db.query(Asset).count()
        
        # Count assets that could be affected (have services with CPE references)
        assets_with_services = db.query(Asset).filter(
            or_(
                Asset.primary_service.isnot(None),
                Asset.cpe_name_id.isnot(None),
                Asset.additional_services.isnot(None)
            )
        ).count()
        
        # Count critical assets that could be affected
        critical_assets = db.query(Asset).filter(
            and_(
                Asset.criticality.in_(['critical', 'high']),
                or_(
                    Asset.primary_service.isnot(None),
                    Asset.cpe_name_id.isnot(None)
                )
            )
        ).count()
        
        # Get environments with assets
        environments = db.query(Asset.environment).distinct().all()
        environment_list = [env[0] for env in environments if env[0]]
        
        return {
            "total_cves": total_cves,
            "correlated_cves": correlated_cves,
            "correlation_coverage": (correlated_cves / total_cves * 100) if total_cves > 0 else 0,
            "total_assets": total_assets,
            "assets_with_services": assets_with_services,
            "critical_assets_with_services": critical_assets,
            "environments_affected": environment_list,
            "asset_coverage": (assets_with_services / total_assets * 100) if total_assets > 0 else 0
        }
        
    except Exception as e:
        logger.error(f"Failed to get correlation stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve statistics: {str(e)}")

@router.post("/correlate-with-assets")
async def correlate_cves_with_assets(
    background_tasks: BackgroundTasks,
    confidence_threshold: float = 0.7,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Run correlation analysis between CVEs and assets"""
    if current_user.role not in ["admin", "manager"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    async def run_asset_correlation():
        try:
            stats = await correlate_cves_to_assets(db, confidence_threshold)
            logger.info(f"Asset correlation completed: {stats}")
        except Exception as e:
            logger.error(f"Asset correlation failed: {e}")
    
    background_tasks.add_task(run_asset_correlation)
    return {"message": f"Asset correlation analysis started with confidence threshold {confidence_threshold}"}

@router.get("/assets-at-risk")
async def get_assets_at_risk(
    severity_filter: Optional[str] = None,
    environment_filter: Optional[str] = None,
    criticality_filter: Optional[str] = None,
    confidence_min: float = 0.7,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get assets that are potentially at risk based on CVE correlations"""
    try:
        # Start with assets that have identifiable services
        query = db.query(Asset).filter(
            or_(
                Asset.primary_service.isnot(None),
                Asset.cpe_name_id.isnot(None),
                Asset.additional_services.isnot(None)
            )
        )
        
        # Apply filters
        if environment_filter:
            query = query.filter(Asset.environment == environment_filter)
        
        if criticality_filter:
            query = query.filter(Asset.criticality == criticality_filter)
        
        assets = query.all()
        
        # For each asset, find potential CVE matches
        assets_at_risk = []
        for asset in assets:
            risk_score = 0
            matching_cves = []
            
            # Simple correlation based on service names and vendors
            if asset.primary_service:
                # Find CVEs that might affect this asset's primary service
                cve_matches = db.query(CVE).filter(
                    or_(
                        CVE.description.ilike(f"%{asset.primary_service}%"),
                        CVE.description.ilike(f"%{asset.service_vendor}%") if asset.service_vendor else False
                    )
                ).all()
                
                for cve in cve_matches:
                    if severity_filter and cve.severity != severity_filter:
                        continue
                    
                    matching_cves.append({
                        "cve_id": cve.cve_id,
                        "severity": cve.severity,
                        "cvss_score": cve.cvss_score,
                        "description": cve.description[:200] + "..." if len(cve.description) > 200 else cve.description
                    })
                    
                    # Calculate risk score
                    if cve.cvss_score:
                        risk_score += cve.cvss_score
            
            # Check additional services
            if asset.additional_services:
                for service in asset.additional_services:
                    service_name = service.get('name', '')
                    if service_name:
                        additional_cves = db.query(CVE).filter(
                            CVE.description.ilike(f"%{service_name}%")
                        ).all()
                        
                        for cve in additional_cves:
                            if severity_filter and cve.severity != severity_filter:
                                continue
                            
                            # Avoid duplicate CVEs
                            if not any(mc['cve_id'] == cve.cve_id for mc in matching_cves):
                                matching_cves.append({
                                    "cve_id": cve.cve_id,
                                    "severity": cve.severity,
                                    "cvss_score": cve.cvss_score,
                                    "description": cve.description[:200] + "..." if len(cve.description) > 200 else cve.description,
                                    "affects_service": service_name
                                })
                                
                                if cve.cvss_score:
                                    risk_score += cve.cvss_score * 0.5  # Lower weight for additional services
            
            if matching_cves:
                assets_at_risk.append({
                    "asset": {
                        "id": asset.id,
                        "name": asset.name,
                        "asset_type": asset.asset_type,
                        "ip_address": asset.ip_address,
                        "hostname": asset.hostname,
                        "primary_service": asset.primary_service,
                        "service_vendor": asset.service_vendor,
                        "service_version": asset.service_version,
                        "environment": asset.environment,
                        "criticality": asset.criticality,
                        "location": asset.location,
                        "owner_team": asset.owner_team
                    },
                    "risk_score": risk_score,
                    "matching_cves": matching_cves,
                    "cve_count": len(matching_cves)
                })
        
        # Sort by risk score descending
        assets_at_risk.sort(key=lambda x: x["risk_score"], reverse=True)
        
        return {
            "total_assets_analyzed": len(assets),
            "assets_at_risk": len(assets_at_risk),
            "risk_analysis": assets_at_risk[:50]  # Limit to top 50 for performance
        }
        
    except Exception as e:
        logger.error(f"Failed to get assets at risk: {e}")
        raise HTTPException(status_code=500, detail=f"Risk analysis failed: {str(e)}")

# Main CVE endpoints
@router.get("/", response_model=List[CVEResponse])
async def get_cves(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    environment: Optional[str] = None,
    asset_type: Optional[str] = None,
    correlation_confidence_min: Optional[float] = None,
    include_asset_correlations: bool = False,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get CVEs with enhanced filtering based on assets"""
    try:
        query = db.query(CVE)
        
        if severity:
            query = query.filter(CVE.severity == severity)
        
        if correlation_confidence_min is not None:
            query = query.filter(CVE.correlation_confidence >= correlation_confidence_min)
        
        # Filter CVEs that might affect specific asset types
        if asset_type:
            # Find CVEs that could affect assets of this type
            # This is a simple text-based correlation - could be enhanced
            query = query.filter(CVE.description.ilike(f"%{asset_type}%"))
        
        # Filter CVEs that might affect assets in specific environment
        if environment:
            # This would need more sophisticated correlation logic
            # For now, we'll get all CVEs and filter on the frontend
            pass
        
        cves = query.offset(skip).limit(limit).all()
        
        # Include asset correlations if requested
        if include_asset_correlations:
            for cve in cves:
                # Simple correlation logic - match CVE description to asset services
                potentially_affected_assets = db.query(Asset).filter(
                    or_(
                        Asset.primary_service.ilike(f"%{cve.description.split()[0] if cve.description else ''}%"),
                        Asset.service_vendor.ilike(f"%{cve.description.split()[0] if cve.description else ''}%")
                    )
                ).limit(10).all()  # Limit for performance
                
                cve.asset_correlations = [
                    {
                        "asset": asset,
                        "confidence_score": 0.5,  # Placeholder confidence
                        "correlation_method": "description_match",
                        "status": "potential"
                    }
                    for asset in potentially_affected_assets
                ]
        
        return cves
        
    except Exception as e:
        logger.error(f"Failed to get CVEs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve CVEs: {str(e)}")

@router.get("/{cve_id}", response_model=CVEResponse)
async def get_cve(
    cve_id: str,
    include_asset_correlations: bool = True,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get specific CVE by ID with asset correlation data"""
    cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    
    if include_asset_correlations:
        # Find assets that might be affected by this CVE
        potentially_affected_assets = await find_affected_assets(db, cve)
        cve.asset_correlations = potentially_affected_assets
    
    return cve

@router.get("/{cve_id}/affected-assets")
async def get_affected_assets(
    cve_id: str,
    confidence_threshold: float = 0.5,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get assets potentially affected by a specific CVE"""
    cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    
    try:
        affected_assets = await find_affected_assets(db, cve, confidence_threshold)
        
        return {
            "cve_id": cve_id,
            "total_potentially_affected": len(affected_assets),
            "high_confidence_matches": len([a for a in affected_assets if a["confidence_score"] >= 0.8]),
            "affected_assets": affected_assets
        }
        
    except Exception as e:
        logger.error(f"Failed to find affected assets for {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Asset correlation failed: {str(e)}")

# Utility functions
async def find_affected_assets(db: Session, cve: CVE, min_confidence: float = 0.5) -> List[Dict]:
    """Find assets potentially affected by a CVE"""
    affected_assets = []
    
    try:
        # Extract potential product names from CVE description
        description_lower = cve.description.lower()
        
        # Look for assets with matching services
        assets = db.query(Asset).filter(
            or_(
                Asset.primary_service.isnot(None),
                Asset.additional_services.isnot(None)
            )
        ).all()
        
        for asset in assets:
            confidence = 0.0
            matching_services = []
            
            # Check primary service
            if asset.primary_service:
                service_lower = asset.primary_service.lower()
                if service_lower in description_lower or any(word in description_lower for word in service_lower.split()):
                    confidence += 0.6
                    matching_services.append(asset.primary_service)
                
                # Check vendor match
                if asset.service_vendor and asset.service_vendor.lower() in description_lower:
                    confidence += 0.3
            
            # Check additional services
            if asset.additional_services:
                for service in asset.additional_services:
                    service_name = service.get('name', '').lower()
                    if service_name and service_name in description_lower:
                        confidence += 0.4
                        matching_services.append(service.get('name'))
            
            # Check CPE correlation if available
            if asset.cpe_name and cve.cpe_entries:
                for cpe_entry in cve.cpe_entries:
                    if asset.cpe_name in cpe_entry:
                        confidence += 0.8
                        break
            
            if confidence >= min_confidence:
                affected_assets.append({
                    "asset": {
                        "id": asset.id,
                        "name": asset.name,
                        "asset_type": asset.asset_type,
                        "ip_address": asset.ip_address,
                        "hostname": asset.hostname,
                        "primary_service": asset.primary_service,
                        "service_vendor": asset.service_vendor,
                        "service_version": asset.service_version,
                        "environment": asset.environment,
                        "criticality": asset.criticality,
                        "location": asset.location,
                        "owner_team": asset.owner_team
                    },
                    "confidence_score": min(confidence, 1.0),
                    "matching_services": matching_services,
                    "correlation_method": "service_name_match",
                    "status": "potential"
                })
    
    except Exception as e:
        logger.error(f"Error in find_affected_assets: {e}")
        return []
    
    # Sort by confidence score descending
    affected_assets.sort(key=lambda x: x["confidence_score"], reverse=True)
    return affected_assets

async def correlate_cves_to_assets(db: Session, confidence_threshold: float = 0.7) -> Dict:
    """Background task to correlate all CVEs with assets"""
    stats = {
        "total_cves": 0,
        "cves_processed": 0,
        "assets_analyzed": 0,
        "correlations_found": 0,
        "high_confidence_correlations": 0
    }
    
    try:
        # Get all CVEs
        cves = db.query(CVE).all()
        stats["total_cves"] = len(cves)
        
        # Get all assets with services
        assets = db.query(Asset).filter(
            or_(
                Asset.primary_service.isnot(None),
                Asset.additional_services.isnot(None)
            )
        ).all()
        stats["assets_analyzed"] = len(assets)
        
        for cve in cves:
            try:
                affected_assets = await find_affected_assets(db, cve, 0.3)  # Lower threshold for background processing
                
                if affected_assets:
                    stats["correlations_found"] += len(affected_assets)
                    stats["high_confidence_correlations"] += len([a for a in affected_assets if a["confidence_score"] >= confidence_threshold])
                    
                    # Update CVE with correlation info
                    cve.correlation_confidence = max(a["confidence_score"] for a in affected_assets)
                    cve.affects_assets = [a["asset"]["id"] for a in affected_assets if a["confidence_score"] >= confidence_threshold]
                
                stats["cves_processed"] += 1
                
            except Exception as e:
                logger.error(f"Error correlating CVE {cve.cve_id}: {e}")
                continue
        
        db.commit()
        
    except Exception as e:
        logger.error(f"Asset correlation task failed: {e}")
        db.rollback()
    
    return stats