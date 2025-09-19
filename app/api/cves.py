"""
Cleaned CVE API Endpoints - Asset-Based Architecture
app/api/cves.py

Clean implementation focused on:
- Asset-based CVE correlation
- CPE-based vulnerability assessment
- Asset risk analysis
- No service-based dependencies
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, field_validator
import logging
import json

from app.core.database import get_db
from app.models.cve import CVE
from app.models.asset import Asset
from app.api.auth import get_current_user
from app.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter()

# Pydantic Models
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

class CVEResponse(BaseModel):
    """CVE response with asset correlation information"""
    id: int
    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: Optional[str]
    published_date: Optional[str]
    
    # Asset correlation fields
    affected_products: Optional[Dict[str, Any]] = None
    cpe_entries: Optional[List[str]] = None
    correlation_confidence: Optional[float] = None
    potentially_affected_assets: Optional[int] = None
    
    # AI enhancement fields (if available)
    ai_risk_score: Optional[float] = None
    ai_summary: Optional[str] = None
    mitigation_suggestions: Optional[str] = None
    
    @field_validator('published_date', mode='before')
    @classmethod
    def convert_datetime_to_string(cls, v):
        if isinstance(v, datetime):
            return v.isoformat()
        return v
    
    class Config:
        from_attributes = True

class AssetVulnerabilityResponse(BaseModel):
    """Asset with its vulnerability assessment"""
    asset: AssetResponse
    vulnerability_count: int
    critical_cves: int
    high_cves: int
    medium_cves: int
    low_cves: int
    risk_score: float
    most_critical_cve: Optional[str] = None
    
class CollectionRequest(BaseModel):
    """CVE collection request parameters"""
    days_back: int = 7
    use_files: bool = True
    force_refresh: bool = False

class CorrelationRequest(BaseModel):
    """Asset correlation request parameters"""
    confidence_threshold: float = 0.7
    include_low_confidence: bool = False
    asset_filter: Optional[str] = None

# Statistics and Information Endpoints
@router.get("/stats")
async def get_cve_statistics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get comprehensive CVE and asset correlation statistics"""
    try:
        # Basic CVE statistics
        total_cves = db.query(CVE).count()
        recent_cves = db.query(CVE).filter(
            CVE.published_date >= datetime.now().replace(day=1)  # This month
        ).count()
        
        # Severity breakdown
        severity_stats = db.query(
            CVE.severity,
            func.count(CVE.id)
        ).group_by(CVE.severity).all()
        
        severity_breakdown = {severity or 'unknown': count for severity, count in severity_stats}
        
        # Asset correlation statistics
        total_assets = db.query(Asset).count()
        assets_with_services = db.query(Asset).filter(
            or_(
                Asset.primary_service.isnot(None),
                Asset.cpe_name_id.isnot(None),
                Asset.additional_services.isnot(None)
            )
        ).count()
        
        # Critical assets
        critical_assets = db.query(Asset).filter(
            Asset.criticality.in_(['critical', 'high'])
        ).count()
        
        # Environment breakdown
        env_stats = db.query(
            Asset.environment,
            func.count(Asset.id)
        ).group_by(Asset.environment).all()
        
        environment_breakdown = {env: count for env, count in env_stats}
        
        # CVEs with correlation confidence
        correlated_cves = db.query(CVE).filter(
            CVE.correlation_confidence > 0
        ).count()
        
        return {
            "cve_statistics": {
                "total_cves": total_cves,
                "recent_cves": recent_cves,
                "severity_breakdown": severity_breakdown,
                "correlated_cves": correlated_cves,
                "correlation_coverage": (correlated_cves / total_cves * 100) if total_cves > 0 else 0
            },
            "asset_statistics": {
                "total_assets": total_assets,
                "assets_with_services": assets_with_services,
                "critical_assets": critical_assets,
                "environment_breakdown": environment_breakdown,
                "asset_coverage": (assets_with_services / total_assets * 100) if total_assets > 0 else 0
            },
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get CVE statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve statistics: {str(e)}")

# CVE Collection Endpoints
@router.post("/collect")
async def collect_cves(
    background_tasks: BackgroundTasks,
    request: CollectionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start CVE collection process"""
    if current_user.role not in ["admin", "manager"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    async def run_collection():
        try:
            from app.services.cve_collector import CVECollector
            
            collector = CVECollector()
            stats = await collector.run_asset_focused_collection(
                db, 
                days_back=request.days_back,
                use_files=request.use_files
            )
            
            logger.info(f"CVE collection completed: {stats}")
        except Exception as e:
            logger.error(f"CVE collection failed: {e}")
    
    background_tasks.add_task(run_collection)
    
    return {
        "message": "CVE collection started",
        "parameters": {
            "days_back": request.days_back,
            "use_files": request.use_files,
            "force_refresh": request.force_refresh
        },
        "status": "background_task_started"
    }

@router.post("/collect-immediate")
async def collect_cves_immediate(
    request: CollectionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Collect CVEs immediately (not as background task)"""
    if current_user.role not in ["admin", "manager"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    try:
        from app.services.cve_collector import CVECollector
        
        collector = CVECollector()
        stats = await collector.run_asset_focused_collection(
            db,
            days_back=request.days_back,
            use_files=request.use_files
        )
        
        return {
            "message": "CVE collection completed",
            "statistics": stats,
            "parameters": {
                "days_back": request.days_back,
                "use_files": request.use_files
            }
        }
        
    except Exception as e:
        logger.error(f"Immediate CVE collection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Collection failed: {str(e)}")

# CVE Retrieval Endpoints
@router.get("/", response_model=List[CVEResponse])
async def get_cves(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    environment_filter: Optional[str] = None,
    correlation_confidence_min: Optional[float] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get CVEs with filtering options"""
    try:
        query = db.query(CVE)
        
        # Apply filters
        if severity:
            query = query.filter(CVE.severity == severity.upper())
        
        if correlation_confidence_min is not None:
            query = query.filter(CVE.correlation_confidence >= correlation_confidence_min)
        
        if search:
            query = query.filter(
                or_(
                    CVE.cve_id.ilike(f"%{search}%"),
                    CVE.description.ilike(f"%{search}%")
                )
            )
        
        # Order by severity and date
        severity_order = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }
        
        cves = query.order_by(
            CVE.published_date.desc()
        ).offset(skip).limit(limit).all()
        
        # Add potentially affected assets count for each CVE
        for cve in cves:
            if environment_filter:
                # Count assets in specific environment that might be affected
                asset_count = db.query(Asset).filter(
                    and_(
                        Asset.environment == environment_filter,
                        or_(
                            Asset.primary_service.isnot(None),
                            Asset.cpe_name_id.isnot(None)
                        )
                    )
                ).count()
                cve.potentially_affected_assets = asset_count
            else:
                cve.potentially_affected_assets = None
        
        return cves
        
    except Exception as e:
        logger.error(f"Failed to get CVEs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve CVEs: {str(e)}")

@router.get("/{cve_id}")
async def get_cve_details(
    cve_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed information about a specific CVE"""
    try:
        cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        # Find potentially affected assets
        potentially_affected = []
        
        if cve.cpe_entries:
            # Simple CPE-based matching
            for cpe in cve.cpe_entries:
                if cpe and len(cpe) > 10:  # Basic CPE validation
                    try:
                        # Parse CPE (cpe:2.3:a:vendor:product:version:...)
                        parts = cpe.split(':')
                        if len(parts) >= 5:
                            vendor = parts[3] if parts[3] != '*' else ''
                            product = parts[4] if parts[4] != '*' else ''
                            
                            if vendor or product:
                                # Find matching assets
                                asset_query = db.query(Asset)
                                conditions = []
                                
                                if vendor:
                                    conditions.extend([
                                        Asset.service_vendor.ilike(f"%{vendor}%"),
                                        Asset.vendor.ilike(f"%{vendor}%")
                                    ])
                                
                                if product:
                                    conditions.extend([
                                        Asset.primary_service.ilike(f"%{product}%"),
                                        Asset.operating_system.ilike(f"%{product}%")
                                    ])
                                
                                if conditions:
                                    matching_assets = asset_query.filter(
                                        or_(*conditions)
                                    ).limit(50).all()
                                    
                                    for asset in matching_assets:
                                        if asset.id not in [a['asset']['id'] for a in potentially_affected]:
                                            potentially_affected.append({
                                                'asset': {
                                                    'id': asset.id,
                                                    'name': asset.name,
                                                    'asset_type': asset.asset_type,
                                                    'environment': asset.environment,
                                                    'criticality': asset.criticality,
                                                    'primary_service': asset.primary_service,
                                                    'service_vendor': asset.service_vendor
                                                },
                                                'match_reason': f"CPE match: {vendor}/{product}",
                                                'confidence': 0.7  # Placeholder confidence
                                            })
                    
                    except Exception as e:
                        logger.debug(f"Error parsing CPE {cpe}: {e}")
        
        return {
            'cve': cve,
            'potentially_affected_assets': potentially_affected[:20],  # Limit results
            'total_potentially_affected': len(potentially_affected),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get CVE details for {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve CVE details: {str(e)}")

# Asset Vulnerability Assessment Endpoints
@router.get("/assets-at-risk", response_model=List[AssetVulnerabilityResponse])
async def get_assets_at_risk(
    environment_filter: Optional[str] = None,
    criticality_filter: Optional[str] = None,
    min_vulnerability_count: int = 1,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get assets that are potentially at risk based on CVE correlations"""
    try:
        # Start with assets that have identifiable services
        asset_query = db.query(Asset).filter(
            or_(
                Asset.primary_service.isnot(None),
                Asset.cpe_name_id.isnot(None),
                Asset.additional_services.isnot(None)
            )
        )
        
        # Apply filters
        if environment_filter:
            asset_query = asset_query.filter(Asset.environment == environment_filter)
        
        if criticality_filter:
            asset_query = asset_query.filter(Asset.criticality == criticality_filter)
        
        assets = asset_query.limit(limit * 2).all()  # Get more for filtering
        
        assets_at_risk = []
        
        for asset in assets:
            # Find potential CVE matches for this asset
            vulnerability_count = 0
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            risk_score = 0.0
            most_critical_cve = None
            highest_cvss = 0.0
            
            # Check primary service
            if asset.primary_service:
                matching_cves = db.query(CVE).filter(
                    or_(
                        CVE.description.ilike(f"%{asset.primary_service}%"),
                        CVE.description.ilike(f"%{asset.service_vendor}%") if asset.service_vendor else False
                    )
                ).all()
                
                for cve in matching_cves:
                    vulnerability_count += 1
                    if cve.severity in severity_counts:
                        severity_counts[cve.severity] += 1
                    
                    if cve.cvss_score and cve.cvss_score > highest_cvss:
                        highest_cvss = cve.cvss_score
                        most_critical_cve = cve.cve_id
                    
                    risk_score += (cve.cvss_score or 5.0) * 0.5  # Weight factor
            
            # Check additional services
            if asset.additional_services:
                for service in asset.additional_services:
                    service_name = service.get('name', '') if isinstance(service, dict) else str(service)
                    if service_name:
                        additional_cves = db.query(CVE).filter(
                            CVE.description.ilike(f"%{service_name}%")
                        ).limit(10).all()
                        
                        for cve in additional_cves:
                            vulnerability_count += 1
                            if cve.severity in severity_counts:
                                severity_counts[cve.severity] += 1
                            
                            risk_score += (cve.cvss_score or 4.0) * 0.3  # Lower weight for additional services
            
            # Apply vulnerability count filter
            if vulnerability_count >= min_vulnerability_count:
                assets_at_risk.append(AssetVulnerabilityResponse(
                    asset=AssetResponse.from_orm(asset),
                    vulnerability_count=vulnerability_count,
                    critical_cves=severity_counts['CRITICAL'],
                    high_cves=severity_counts['HIGH'],
                    medium_cves=severity_counts['MEDIUM'],
                    low_cves=severity_counts['LOW'],
                    risk_score=round(risk_score, 2),
                    most_critical_cve=most_critical_cve
                ))
        
        # Sort by risk score descending
        assets_at_risk.sort(key=lambda x: x.risk_score, reverse=True)
        
        return assets_at_risk[:limit]
        
    except Exception as e:
        logger.error(f"Failed to get assets at risk: {e}")
        raise HTTPException(status_code=500, detail=f"Risk analysis failed: {str(e)}")

@router.get("/asset/{asset_id}/vulnerabilities")
async def get_asset_vulnerabilities(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed vulnerability assessment for a specific asset"""
    try:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        vulnerabilities = []
        
        # Check primary service vulnerabilities
        if asset.primary_service:
            primary_cves = db.query(CVE).filter(
                or_(
                    CVE.description.ilike(f"%{asset.primary_service}%"),
                    CVE.description.ilike(f"%{asset.service_vendor}%") if asset.service_vendor else False
                )
            ).limit(100).all()
            
            for cve in primary_cves:
                vulnerabilities.append({
                    'cve': CVEResponse.from_orm(cve),
                    'affects_service': asset.primary_service,
                    'match_confidence': 0.6,  # Placeholder confidence
                    'match_method': 'service_name_match'
                })
        
        # Check additional services
        if asset.additional_services:
            for service in asset.additional_services:
                service_name = service.get('name', '') if isinstance(service, dict) else str(service)
                if service_name:
                    service_cves = db.query(CVE).filter(
                        CVE.description.ilike(f"%{service_name}%")
                    ).limit(20).all()
                    
                    for cve in service_cves:
                        # Avoid duplicates
                        if not any(v['cve'].cve_id == cve.cve_id for v in vulnerabilities):
                            vulnerabilities.append({
                                'cve': CVEResponse.from_orm(cve),
                                'affects_service': service_name,
                                'match_confidence': 0.5,
                                'match_method': 'additional_service_match'
                            })
        
        # Sort by CVSS score descending
        vulnerabilities.sort(
            key=lambda x: x['cve'].cvss_score or 0.0,
            reverse=True
        )
        
        # Calculate summary statistics
        total_vulns = len(vulnerabilities)
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_risk_score = 0.0
        
        for vuln in vulnerabilities:
            cve = vuln['cve']
            if cve.severity in severity_counts:
                severity_counts[cve.severity] += 1
            
            if cve.cvss_score:
                total_risk_score += cve.cvss_score * vuln['match_confidence']
        
        return {
            'asset': AssetResponse.from_orm(asset),
            'vulnerability_summary': {
                'total_vulnerabilities': total_vulns,
                'critical_count': severity_counts['CRITICAL'],
                'high_count': severity_counts['HIGH'],
                'medium_count': severity_counts['MEDIUM'],
                'low_count': severity_counts['LOW'],
                'total_risk_score': round(total_risk_score, 2)
            },
            'vulnerabilities': vulnerabilities[:50],  # Limit to top 50
            'analysis_timestamp': datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get vulnerabilities for asset {asset_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Vulnerability assessment failed: {str(e)}")

# Testing and Utility Endpoints
@router.get("/test-collection")
async def test_cve_collection(
    days_back: int = 1,
    use_files: bool = True,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Test CVE collection functionality"""
    if current_user.role not in ["admin", "manager"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    try:
        from app.services.cve_collector import CVECollector
        
        collector = CVECollector()
        
        # Test asset keyword extraction
        asset_keywords = collector.get_asset_keywords(db)
        
        # Test collection method
        if use_files:
            test_result = await collector.collect_cves_from_files(db, days_back)
        else:
            test_result = await collector.collect_recent_cves_api(db, days_back)
        
        return {
            "test_completed": True,
            "method_used": "files" if use_files else "api",
            "days_back": days_back,
            "asset_keywords_found": len(asset_keywords),
            "sample_keywords": list(asset_keywords)[:10],
            "cves_found": len(test_result) if test_result else 0,
            "sample_cves": [cve.get('cve_id') for cve in test_result[:5]] if test_result else [],
            "test_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"CVE collection test failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")

# Legacy compatibility endpoints (redirects)
@router.post("/enhance-collection")
async def legacy_enhance_collection(
    background_tasks: BackgroundTasks,
    days_back: int = 7,
    use_files: bool = True,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Legacy endpoint - redirects to new collect endpoint"""
    logger.info("Legacy enhance-collection endpoint called - redirecting to /collect")
    
    request = CollectionRequest(days_back=days_back, use_files=use_files)
    return await collect_cves(background_tasks, request, current_user, db)

@router.post("/manual-collect")
async def legacy_manual_collect(
    days_back: int = 1,
    use_files: bool = True,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Legacy endpoint - redirects to immediate collection"""
    logger.info("Legacy manual-collect endpoint called - redirecting to /collect-immediate")
    
    request = CollectionRequest(days_back=days_back, use_files=use_files)
    return await collect_cves_immediate(request, current_user, db)

@router.get("/collection-stats")
async def legacy_collection_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Legacy endpoint - redirects to stats endpoint"""
    logger.info("Legacy collection-stats endpoint called - redirecting to /stats")
    return await get_cve_statistics(current_user, db)

@router.get("/test-file-download")
async def legacy_test_download(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Legacy endpoint - redirects to test collection"""
    logger.info("Legacy test-file-download endpoint called - redirecting to /test-collection")
    return await test_cve_collection(1, True, current_user, db)

@router.post("/{cve_id}/analyze")
async def analyze_cve(
    cve_id: str,
    include_asset_correlation: bool = Query(True, description="Include asset correlation analysis"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    AI-powered CVE analysis with asset correlation
    """
    try:
        # Check if CVE exists
        cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if not cve:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
        
        # Check user permissions
        if current_user.role not in ["admin", "manager", "analyst"]:
            raise HTTPException(status_code=403, detail="Insufficient permissions to analyze CVEs")
        
        # Initialize AI agent
        try:
            from app.services.ai_agent import LocalAIAgent
            ai_agent = LocalAIAgent()
        except ImportError as e:
            logger.error(f"Failed to import AI agent: {e}")
            raise HTTPException(status_code=500, detail="AI agent not available")
        
        analysis_results = {
            "cve_id": cve_id,
            "analysis_timestamp": datetime.now().isoformat(),
            "analyzed_by": current_user.username,
            "status": "in_progress"
        }
        
        logger.info(f"Starting AI analysis for CVE {cve_id}")
        
        # Perform AI analysis
        try:
            ai_analysis = await ai_agent.analyze_cve(cve.description, cve_id)
            
            if ai_analysis:
                # Store AI analysis results in CVE record
                cve.ai_risk_score = ai_analysis.get('risk_score')
                cve.ai_summary = ai_analysis.get('summary')
                cve.mitigation_suggestions = json.dumps(ai_analysis.get('mitigations', []))
                cve.detection_methods = json.dumps(ai_analysis.get('detection_methods', []))
                cve.upgrade_paths = json.dumps(ai_analysis.get('upgrade_paths', []))
                
                analysis_results.update({
                    "ai_analysis": {
                        "risk_score": ai_analysis.get('risk_score'),
                        "summary": ai_analysis.get('summary'),
                        "mitigations": ai_analysis.get('mitigations', []),
                        "detection_methods": ai_analysis.get('detection_methods', []),
                        "upgrade_paths": ai_analysis.get('upgrade_paths', [])
                    }
                })
                
                logger.info(f"AI analysis completed for {cve_id} with risk score: {ai_analysis.get('risk_score')}")
                
            else:
                logger.warning(f"AI analysis returned empty result for {cve_id}")
                analysis_results["ai_analysis_warning"] = "AI analysis returned no results"
                
        except Exception as e:
            logger.error(f"AI analysis failed for {cve_id}: {e}")
            analysis_results["ai_analysis_error"] = f"AI analysis failed: {str(e)}"
            
            # Provide fallback analysis
            analysis_results["ai_analysis"] = {
                "risk_score": _derive_fallback_risk_score(cve),
                "summary": f"Manual analysis required for {cve_id}. AI analysis failed.",
                "mitigations": ["Review vendor security advisories", "Apply security patches when available"],
                "detection_methods": ["Check software version inventories", "Monitor for exploitation indicators"],
                "upgrade_paths": ["Consult vendor documentation", "Plan upgrade timeline based on criticality"]
            }
        
        # Asset correlation analysis (if requested)
        if include_asset_correlation:
            try:
                correlation_results = await _perform_asset_correlation(cve, db, ai_analysis)
                analysis_results["asset_correlation"] = correlation_results
                
                # Update CVE correlation confidence
                if correlation_results.get("correlation_confidence", 0) > 0:
                    cve.correlation_confidence = correlation_results["correlation_confidence"]
                    
            except Exception as e:
                logger.error(f"Asset correlation failed for {cve_id}: {e}")
                analysis_results["correlation_error"] = f"Asset correlation failed: {str(e)}"
        
        # Generate comprehensive recommendations based on AI analysis and asset correlation
        recommendations = _generate_recommendations(
            ai_analysis, 
            analysis_results.get("asset_correlation", {}),
            cve
        )
        analysis_results["recommendations"] = recommendations
        
        # Calculate overall risk assessment
        risk_assessment = _calculate_risk_assessment(ai_analysis, analysis_results.get("asset_correlation", {}))
        analysis_results["risk_assessment"] = risk_assessment
        
        # Mark CVE as processed and analyzed
        cve.processed = True
        cve.last_analyzed = datetime.now()
        
        # Commit all changes to database
        db.commit()
        
        analysis_results["status"] = "completed"
        analysis_results["message"] = f"AI-powered analysis completed for CVE {cve_id}"
        
        logger.info(f"Analysis completed for {cve_id}")
        return analysis_results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"CVE analysis failed for {cve_id}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


async def _perform_asset_correlation(cve: CVE, db: Session, ai_analysis: Dict) -> Dict:
    """
    Perform asset correlation analysis using AI insights
    """
    assets = db.query(Asset).filter(Asset.status == 'active').all()
    affected_assets = []
    
    # Extract product information from AI analysis if available
    ai_products = []
    if ai_analysis and ai_analysis.get('summary'):
        # Simple keyword extraction from AI summary
        summary_lower = ai_analysis['summary'].lower()
        common_products = [
            'apache', 'nginx', 'mysql', 'postgresql', 'mongodb', 'redis',
            'wordpress', 'drupal', 'joomla', 'tomcat', 'jenkins', 'gitlab',
            'windows', 'linux', 'ubuntu', 'debian', 'centos', 'rhel',
            'java', 'python', 'node.js', 'php', 'ruby', '.net'
        ]
        
        for product in common_products:
            if product in summary_lower:
                ai_products.append(product)
    
    for asset in assets:
        confidence = 0.0
        match_reasons = []
        
        # Primary service correlation
        if asset.primary_service and cve.description:
            service_lower = asset.primary_service.lower()
            description_lower = cve.description.lower()
            
            # Direct service name match
            if service_lower in description_lower:
                confidence += 0.6
                match_reasons.append(f"Service '{asset.primary_service}' found in CVE description")
            
            # AI-identified product correlation
            for product in ai_products:
                if product in service_lower:
                    confidence += 0.4
                    match_reasons.append(f"AI identified affected product '{product}' matches service")
        
        # Vendor correlation
        if asset.service_vendor and cve.description:
            vendor_lower = asset.service_vendor.lower()
            description_lower = cve.description.lower()
            
            if vendor_lower in description_lower:
                confidence += 0.4
                match_reasons.append(f"Vendor '{asset.service_vendor}' found in CVE description")
        
        # Operating system correlation
        if asset.operating_system and cve.description:
            os_lower = asset.operating_system.lower()
            description_lower = cve.description.lower()
            
            for os_keyword in ['windows', 'linux', 'ubuntu', 'debian', 'centos', 'rhel']:
                if os_keyword in os_lower and os_keyword in description_lower:
                    confidence += 0.3
                    match_reasons.append(f"Operating system '{asset.operating_system}' potentially affected")
        
        # CPE correlation (if available)
        if asset.cpe_name_id and hasattr(cve, 'cpe_entries') and cve.cpe_entries:
            try:
                cpe_entries = json.loads(cve.cpe_entries) if isinstance(cve.cpe_entries, str) else cve.cpe_entries
                if isinstance(cpe_entries, list) and asset.cpe_name_id in cpe_entries:
                    confidence += 0.8
                    match_reasons.append(f"Direct CPE match: {asset.cpe_name_id}")
            except (json.JSONDecodeError, TypeError):
                pass
        
        # AI risk score amplification for critical assets
        if ai_analysis and ai_analysis.get('risk_score', 0) >= 7.0:
            if asset.criticality in ['critical', 'high']:
                confidence *= 1.2  # Amplify correlation for high-risk CVEs on critical assets
                if confidence > 0:
                    match_reasons.append("High-risk CVE on critical asset - elevated correlation")
        
        # Include assets with meaningful correlation
        if confidence > 0.25:
            asset_risk_score = confidence * ai_analysis.get('risk_score', 5.0) / 10.0 if ai_analysis else confidence * 0.5
            
            affected_assets.append({
                "asset_id": asset.id,
                "asset_name": asset.name,
                "asset_type": asset.asset_type,
                "environment": asset.environment,
                "criticality": asset.criticality,
                "confidence": min(confidence, 1.0),
                "asset_risk_score": round(asset_risk_score, 3),
                "match_reasons": match_reasons,
                "primary_service": asset.primary_service,
                "service_vendor": asset.service_vendor,
                "service_version": asset.service_version,
                "operating_system": asset.operating_system,
                "location": asset.location
            })
    
    # Sort by risk score and confidence
    affected_assets.sort(key=lambda x: (x['asset_risk_score'], x['confidence']), reverse=True)
    
    # Calculate correlation confidence
    correlation_confidence = max([a['confidence'] for a in affected_assets]) if affected_assets else 0.0
    
    # Environment risk breakdown
    environment_risk = {}
    for asset in affected_assets:
        env = asset['environment']
        if env not in environment_risk:
            environment_risk[env] = {
                'asset_count': 0,
                'max_risk': 0.0,
                'critical_assets': 0,
                'avg_confidence': 0.0
            }
        
        environment_risk[env]['asset_count'] += 1
        environment_risk[env]['max_risk'] = max(environment_risk[env]['max_risk'], asset['asset_risk_score'])
        environment_risk[env]['avg_confidence'] += asset['confidence']
        
        if asset['criticality'] in ['critical', 'high']:
            environment_risk[env]['critical_assets'] += 1
    
    # Calculate average confidence per environment
    for env_data in environment_risk.values():
        if env_data['asset_count'] > 0:
            env_data['avg_confidence'] = round(env_data['avg_confidence'] / env_data['asset_count'], 3)
    
    return {
        "total_assets_analyzed": len(assets),
        "potentially_affected_assets": len(affected_assets),
        "correlation_confidence": round(correlation_confidence, 3),
        "affected_assets": affected_assets[:25],  # Limit for response size
        "environment_risk": environment_risk,
        "ai_products_identified": ai_products
    }


def _generate_recommendations(ai_analysis: Dict, correlation_data: Dict, cve: CVE) -> List[str]:
    """
    Generate actionable recommendations based on AI analysis and asset correlation
    """
    recommendations = []
    
    # AI-based recommendations
    if ai_analysis:
        risk_score = ai_analysis.get('risk_score', 0)
        
        if risk_score >= 9.0:
            recommendations.append("🚨 CRITICAL: Immediate emergency response required")
            recommendations.append("🚨 Activate incident response procedures")
        elif risk_score >= 7.0:
            recommendations.append("⚠️  HIGH PRIORITY: Address within 24-48 hours")
        elif risk_score >= 4.0:
            recommendations.append("📋 MEDIUM PRIORITY: Plan remediation within 1-2 weeks")
        else:
            recommendations.append("📝 LOW PRIORITY: Include in routine patching cycle")
        
        # Add AI-generated mitigations
        if ai_analysis.get('mitigations'):
            for mitigation in ai_analysis['mitigations'][:3]:  # Top 3 mitigations
                recommendations.append(f"🛡️  {mitigation}")
    
    # Asset correlation-based recommendations
    if correlation_data:
        affected_count = correlation_data.get('potentially_affected_assets', 0)
        
        if affected_count > 0:
            recommendations.append(f"🔍 Review {affected_count} potentially affected assets")
            
            # Environment-specific recommendations
            env_risk = correlation_data.get('environment_risk', {})
            for env, risk_data in env_risk.items():
                if risk_data['critical_assets'] > 0:
                    recommendations.append(f"🏭 Prioritize {risk_data['critical_assets']} critical assets in {env} environment")
        
        # High correlation confidence recommendations
        if correlation_data.get('correlation_confidence', 0) >= 0.7:
            recommendations.append("📊 High confidence correlations found - prioritize asset verification")
        
    # General security recommendations
    if cve.severity in ['CRITICAL', 'HIGH']:
        recommendations.append("🔄 Check for available security patches")
        recommendations.append("📡 Monitor for signs of active exploitation")
        recommendations.append("🔒 Consider temporary mitigations if patches unavailable")
    
    recommendations.append("📋 Update asset inventory and software versions")
    recommendations.append("📈 Review and update vulnerability management processes")
    
    return recommendations


def _calculate_risk_assessment(ai_analysis: Dict, correlation_data: Dict) -> Dict:
    """
    Calculate overall risk assessment combining AI and correlation analysis
    """
    base_risk = ai_analysis.get('risk_score', 5.0) if ai_analysis else 5.0
    
    # Amplify risk based on asset correlation
    affected_assets = correlation_data.get('potentially_affected_assets', 0)
    correlation_confidence = correlation_data.get('correlation_confidence', 0)
    
    # Risk amplification factors
    asset_factor = min(1 + (affected_assets * 0.1), 2.0)  # Max 2x amplification
    confidence_factor = 1 + (correlation_confidence * 0.3)  # Up to 30% amplification
    
    adjusted_risk = base_risk * asset_factor * confidence_factor
    adjusted_risk = min(adjusted_risk, 10.0)  # Cap at 10.0
    
    # Risk level determination
    if adjusted_risk >= 8.5:
        risk_level = "CRITICAL"
        urgency = "immediate"
    elif adjusted_risk >= 7.0:
        risk_level = "HIGH"
        urgency = "urgent"
    elif adjusted_risk >= 4.0:
        risk_level = "MEDIUM"
        urgency = "planned"
    else:
        risk_level = "LOW"
        urgency = "routine"
    
    return {
        "base_risk_score": round(base_risk, 2),
        "adjusted_risk_score": round(adjusted_risk, 2),
        "risk_level": risk_level,
        "urgency": urgency,
        "affected_assets": affected_assets,
        "correlation_confidence": correlation_confidence,
        "requires_immediate_attention": adjusted_risk >= 8.5 or (
            affected_assets > 0 and 
            correlation_confidence > 0.7 and 
            base_risk >= 7.0
        )
    }


def _derive_fallback_risk_score(cve: CVE) -> float:
    """
    Derive a fallback risk score when AI analysis fails
    """
    score = 5.0  # Default medium risk
    
    if cve.cvss_score:
        score = cve.cvss_score
    elif cve.severity:
        severity_scores = {
            'CRITICAL': 9.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 3.0
        }
        score = severity_scores.get(cve.severity.upper(), 5.0)
    
    # Check for high-risk keywords in description
    if cve.description:
        high_risk_keywords = [
            'remote code execution', 'privilege escalation', 'authentication bypass',
            'buffer overflow', 'sql injection', 'memory corruption'
        ]
        
        description_lower = cve.description.lower()
        for keyword in high_risk_keywords:
            if keyword in description_lower:
                score = min(score + 1.0, 10.0)
                break
    
    return round(score, 1)