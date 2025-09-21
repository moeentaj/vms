"""
Cleaned CVE API Endpoints - Asset-Based Architecture
app/api/cves.py

Clean implementation focused on:
- Asset-based CVE correlation
- CPE-based vulnerability assessment
- Asset risk analysis
- Removed legacy service-based endpoints
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

# Core CVE Collection Endpoints
@router.post("/collect")
async def collect_cves(
    background_tasks: BackgroundTasks,
    request: CollectionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start CVE collection in background"""
    try:
        # Import here to avoid circular dependencies
        from app.services.cve_collector import CVECollector
        
        collector = CVECollector()
        
        # Start collection in background
        background_tasks.add_task(
            collector.collect_and_process_cves,
            db=db,
            days_back=request.days_back,
            use_files=request.use_files,
            force_refresh=request.force_refresh
        )
        
        logger.info(f"CVE collection started for {request.days_back} days (background)")
        
        return {
            "status": "started",
            "days_back": request.days_back,
            "use_files": request.use_files,
            "message": f"CVE collection started for last {request.days_back} days"
        }
        
    except Exception as e:
        logger.error(f"Failed to start CVE collection: {e}")
        raise HTTPException(status_code=500, detail=f"Collection failed: {str(e)}")

@router.post("/collect-immediate")
async def collect_cves_immediate(
    request: CollectionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Collect CVEs immediately (for small collections)"""
    
    # Limit immediate collection to prevent timeouts
    if request.days_back > 3:
        raise HTTPException(
            status_code=400,
            detail="Immediate collection limited to 3 days. Use /collect for larger collections."
        )
    
    try:
        from app.services.cve_collector import CVECollector
        
        collector = CVECollector()
        
        # Collect immediately
        result = await collector.collect_and_process_cves(
            db=db,
            days_back=request.days_back,
            use_files=request.use_files,
            force_refresh=request.force_refresh
        )
        
        return {
            "status": "completed",
            "collected_count": result.get("stored", 0),
            "updated_count": result.get("updated", 0),
            "days_back": request.days_back,
            "message": f"Collected {result.get('stored', 0)} new CVEs"
        }
        
    except Exception as e:
        logger.error(f"Immediate CVE collection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Collection failed: {str(e)}")

@router.get("/test-collection")
async def test_cve_collection(
    days_back: int = Query(1, ge=1, le=7, description="Days to test"),
    use_files: bool = Query(True, description="Use file-based collection"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Test CVE collection without storing data"""
    try:
        from app.services.cve_collector import CVECollector
        
        collector = CVECollector()
        
        # Test collection without storing
        test_result = await collector.test_collection(
            days_back=days_back,
            use_files=use_files
        )
        
        return {
            "status": "test_completed",
            "would_collect": test_result.get("potential_cves", 0),
            "test_sample": test_result.get("sample_cves", []),
            "days_tested": days_back,
            "message": f"Test found {test_result.get('potential_cves', 0)} CVEs"
        }
        
    except Exception as e:
        logger.error(f"CVE collection test failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")

# CVE Retrieval Endpoints
@router.get("/", response_model=List[CVEResponse])
async def get_cves(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=500, description="Number of records to return"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    environment_filter: Optional[str] = Query(None, description="Filter by environment"),
    correlation_confidence_min: Optional[float] = Query(None, ge=0.0, le=1.0),
    search: Optional[str] = Query(None, description="Search term"),
    processed: Optional[bool] = Query(None, description="Filter by processing status"),
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
        
        if processed is not None:
            query = query.filter(CVE.processed == processed)
        
        if search:
            query = query.filter(
                or_(
                    CVE.cve_id.ilike(f"%{search}%"),
                    CVE.description.ilike(f"%{search}%")
                )
            )
        
        # Order by severity and date
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
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
        
        # Get potentially affected assets
        potentially_affected = []
        if cve.cpe_entries:
            try:
                cpe_list = json.loads(cve.cpe_entries) if isinstance(cve.cpe_entries, str) else cve.cpe_entries
                if cpe_list:
                    # Find assets that might be affected based on CPE matching
                    assets = db.query(Asset).filter(
                        or_(
                            Asset.cpe_name_id.in_(cpe_list),
                            Asset.primary_service.isnot(None)
                        )
                    ).all()
                    
                    potentially_affected = [
                        {
                            "asset_id": asset.id,
                            "name": asset.name,
                            "environment": asset.environment,
                            "criticality": asset.criticality,
                            "match_confidence": 0.8  # Default confidence
                        }
                        for asset in assets[:20]  # Limit results
                    ]
            except (json.JSONDecodeError, TypeError):
                potentially_affected = []
        
        return {
            "cve": cve,
            "potentially_affected_assets": potentially_affected,
            "affected_asset_count": len(potentially_affected)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get CVE details: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve CVE: {str(e)}")

# CVE Analysis Endpoints
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
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        # Import AI agent (your existing LocalAIAgent)
        try:
            from app.services.ai_agent import LocalAIAgent
            ai_agent = LocalAIAgent()
        except ImportError:
            logger.warning("AI agent not available, skipping AI analysis")
            ai_agent = None
        
        # Perform AI analysis if available
        ai_analysis = None
        if ai_agent:
            try:
                ai_analysis = await ai_agent.analyze_cve(cve.description, cve_id)
                
                # Update CVE with AI analysis
                if ai_analysis:
                    cve.ai_risk_score = ai_analysis.get("risk_score")
                    cve.ai_summary = ai_analysis.get("summary")
                    cve.mitigation_suggestions = json.dumps(ai_analysis.get("mitigations", []))
                    cve.detection_methods = json.dumps(ai_analysis.get("detection_methods", []))
                    cve.upgrade_paths = json.dumps(ai_analysis.get("upgrade_paths", []))
                    cve.processed = True
                    cve.last_analyzed = datetime.now()
                
            except Exception as ai_error:
                logger.error(f"AI analysis failed for {cve_id}: {ai_error}")
                ai_analysis = {"error": "AI analysis failed", "details": str(ai_error)}
        
        # Asset correlation analysis
        asset_correlation = None
        if include_asset_correlation:
            try:
                from app.services.cpe_cve_correlation import CPECVECorrelationEngine
                correlation_engine = CPECVECorrelationEngine(db)
                asset_correlation = await correlation_engine.correlate_cve_to_assets(cve_id)
                
                # Update CVE with correlation data
                if asset_correlation:
                    cve.correlation_confidence = asset_correlation.get("confidence_score", 0.0)
                    cve.potentially_affected_assets = asset_correlation.get("total_potentially_affected", 0)
                
            except Exception as corr_error:
                logger.error(f"Asset correlation failed for {cve_id}: {corr_error}")
                asset_correlation = {"error": "Asset correlation failed", "details": str(corr_error)}
        
        # Save updates
        db.commit()
        
        return {
            "cve_id": cve_id,
            "analysis_status": "completed",
            "ai_analysis": ai_analysis,
            "asset_correlation": asset_correlation,
            "updated_fields": {
                "ai_risk_score": cve.ai_risk_score,
                "correlation_confidence": cve.correlation_confidence,
                "potentially_affected_assets": cve.potentially_affected_assets,
                "processed": cve.processed
            },
            "analysis_timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"CVE analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# Asset-CVE Correlation Endpoints
@router.get("/{cve_id}/affected-assets")
async def get_affected_assets(
    cve_id: str,
    environment: Optional[str] = Query(None, description="Filter by environment"),
    confidence_threshold: float = Query(0.5, ge=0.0, le=1.0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get assets potentially affected by a CVE"""
    try:
        cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if not cve:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
        
        # Use correlation engine if available
        try:
            from app.services.cpe_cve_correlation import CPECVECorrelationEngine
            correlation_engine = CPECVECorrelationEngine(db)
            
            affected_assets = await correlation_engine.get_enhanced_affected_assets(
                cve_id=cve_id,
                environment_filter=environment,
                confidence_threshold=confidence_threshold
            )
            
            return affected_assets
            
        except ImportError:
            # Fallback to basic CPE matching
            logger.warning("Correlation engine not available, using basic matching")
            
            affected_assets = []
            if cve.cpe_entries:
                try:
                    cpe_list = json.loads(cve.cpe_entries) if isinstance(cve.cpe_entries, str) else cve.cpe_entries
                    if cpe_list:
                        query = db.query(Asset)
                        
                        if environment:
                            query = query.filter(Asset.environment == environment)
                        
                        assets = query.filter(
                            or_(
                                Asset.cpe_name_id.in_(cpe_list),
                                Asset.primary_service.isnot(None)
                            )
                        ).all()
                        
                        affected_assets = [
                            {
                                "asset_id": asset.id,
                                "name": asset.name,
                                "environment": asset.environment,
                                "criticality": asset.criticality,
                                "confidence_score": 0.7,  # Default confidence
                                "match_reason": "Basic CPE matching"
                            }
                            for asset in assets
                        ]
                except (json.JSONDecodeError, TypeError):
                    affected_assets = []
            
            return {
                "cve_id": cve_id,
                "total_potentially_affected": len(affected_assets),
                "affected_assets": affected_assets
            }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get affected assets: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get affected assets: {str(e)}")

# Statistics and Reporting
@router.get("/stats")
async def get_cve_statistics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get CVE statistics and metrics"""
    try:
        # Basic CVE statistics
        total_cves = db.query(CVE).count()
        processed_cves = db.query(CVE).filter(CVE.processed == True).count()
        
        # Severity breakdown
        severity_stats = {}
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = db.query(CVE).filter(CVE.severity == severity).count()
            severity_stats[severity.lower()] = count
        
        # Recent activity
        from datetime import timedelta
        week_ago = datetime.now() - timedelta(days=7)
        recent_cves = db.query(CVE).filter(CVE.published_date >= week_ago).count()
        
        # Asset correlation stats
        correlated_cves = db.query(CVE).filter(
            CVE.correlation_confidence.isnot(None)
        ).count()
        
        return {
            "total_cves": total_cves,
            "processed_cves": processed_cves,
            "processing_rate": round((processed_cves / total_cves * 100), 2) if total_cves > 0 else 0,
            "severity_breakdown": severity_stats,
            "recent_cves_7_days": recent_cves,
            "correlated_cves": correlated_cves,
            "correlation_rate": round((correlated_cves / total_cves * 100), 2) if total_cves > 0 else 0,
            "last_updated": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get CVE statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")

# Asset Vulnerability Assessment
@router.get("/asset-vulnerabilities/{asset_id}")
async def get_asset_vulnerabilities(
    asset_id: int,
    severity_filter: Optional[str] = Query(None, description="Filter by severity"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all CVEs that potentially affect a specific asset"""
    try:
        # Check if asset exists
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
        
        # Use correlation engine if available
        try:
            from app.services.cpe_cve_correlation import CPECVECorrelationEngine
            correlation_engine = CPECVECorrelationEngine(db)
            
            assessment = await correlation_engine.assess_asset_vulnerabilities(asset_id)
            return assessment
            
        except ImportError:
            # Fallback to basic matching
            logger.warning("Correlation engine not available, using basic matching")
            
            cves_query = db.query(CVE)
            
            if severity_filter:
                cves_query = cves_query.filter(CVE.severity == severity_filter.upper())
            
            # Basic CPE matching logic would go here
            relevant_cves = cves_query.limit(50).all()  # Limit for performance
            
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for cve in relevant_cves:
                if cve.severity:
                    severity_counts[cve.severity.lower()] = severity_counts.get(cve.severity.lower(), 0) + 1
            
            return {
                "asset_id": asset_id,
                "asset_name": asset.name,
                "total_cves": len(relevant_cves),
                "severity_breakdown": severity_counts,
                "risk_score": 0.0,  # Would be calculated with proper correlation
                "cves": [{"cve_id": cve.cve_id, "severity": cve.severity, "cvss_score": cve.cvss_score} for cve in relevant_cves]
            }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get asset vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get vulnerabilities: {str(e)}")

# Helper Functions for CVE Analysis
def _derive_fallback_risk_score(cve: CVE) -> float:
    """Derive a basic risk score from CVE data when AI analysis fails"""
    score = 5.0  # Default medium risk
    
    if cve.cvss_score:
        score = cve.cvss_score
    elif cve.severity:
        severity_scores = {
            "CRITICAL": 9.0,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5
        }
        score = severity_scores.get(cve.severity.upper(), 5.0)
    
    # Adjust based on description keywords
    if cve.description:
        desc_lower = cve.description.lower()
        if any(keyword in desc_lower for keyword in ['remote code execution', 'privilege escalation', 'authentication bypass']):
            score = min(score + 1.5, 10.0)
        elif any(keyword in desc_lower for keyword in ['denial of service', 'information disclosure']):
            score = max(score - 0.5, 1.0)
    
    return round(score, 1)

def _perform_asset_correlation(cve: CVE, db: Session, ai_analysis: Dict = None) -> Dict:
    """Perform asset correlation analysis using AI insights"""
    assets = db.query(Asset).filter(Asset.status == 'active').all()
    affected_assets = []
    
    # Extract product information from AI analysis if available
    ai_products = []
    if ai_analysis and ai_analysis.get('summary'):
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
        
        # CPE correlation (if available)
        if hasattr(asset, 'cpe_name_id') and asset.cpe_name_id and hasattr(cve, 'cpe_entries') and cve.cpe_entries:
            try:
                cpe_entries = json.loads(cve.cpe_entries) if isinstance(cve.cpe_entries, str) else cve.cpe_entries
                if isinstance(cpe_entries, list) and asset.cpe_name_id in cpe_entries:
                    confidence += 0.8
                    match_reasons.append(f"Direct CPE match: {asset.cpe_name_id}")
            except (json.JSONDecodeError, TypeError):
                pass
        
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
                "service_vendor": asset.service_vendor
            })
    
    # Calculate overall correlation confidence
    if affected_assets:
        avg_confidence = sum(asset["confidence"] for asset in affected_assets) / len(affected_assets)
        correlation_confidence = min(avg_confidence, 1.0)
    else:
        correlation_confidence = 0.0
    
    return {
        "total_potentially_affected": len(affected_assets),
        "high_confidence_matches": len([a for a in affected_assets if a["confidence"] >= 0.8]),
        "correlation_confidence": correlation_confidence,
        "affected_assets": affected_assets[:20]  # Limit results
    }

def _generate_recommendations(ai_analysis: Dict = None, asset_correlation: Dict = None, cve: CVE = None) -> List[str]:
    """Generate comprehensive recommendations based on analysis"""
    recommendations = []
    
    # AI-based recommendations
    if ai_analysis and ai_analysis.get('mitigations'):
        recommendations.extend(ai_analysis['mitigations'][:3])  # Top 3 AI recommendations
    
    # Asset-based recommendations
    if asset_correlation and asset_correlation.get('total_potentially_affected', 0) > 0:
        affected_count = asset_correlation['total_potentially_affected']
        recommendations.append(f"Review {affected_count} potentially affected assets immediately")
        
        if asset_correlation.get('high_confidence_matches', 0) > 0:
            recommendations.append("Prioritize high-confidence asset matches for immediate patching")
    
    # Severity-based recommendations
    if cve and cve.severity in ['CRITICAL', 'HIGH']:
        recommendations.append("Apply emergency change management process for critical/high severity CVE")
    
    # Default recommendations if none available
    if not recommendations:
        recommendations = [
            "Review vendor security advisories",
            "Check for available patches or updates",
            "Monitor systems for signs of exploitation"
        ]
    
    return recommendations[:5]  # Limit to 5 recommendations

def _calculate_risk_assessment(ai_analysis: Dict = None, asset_correlation: Dict = None) -> Dict:
    """Calculate overall risk assessment"""
    base_risk_score = 5.0
    
    if ai_analysis and ai_analysis.get('risk_score'):
        base_risk_score = ai_analysis['risk_score']
    
    # Adjust based on asset correlation
    if asset_correlation:
        affected_count = asset_correlation.get('total_potentially_affected', 0)
        if affected_count > 10:
            base_risk_score = min(base_risk_score + 1.0, 10.0)
        elif affected_count > 5:
            base_risk_score = min(base_risk_score + 0.5, 10.0)
    
    risk_level = "LOW"
    if base_risk_score >= 8.0:
        risk_level = "CRITICAL"
    elif base_risk_score >= 7.0:
        risk_level = "HIGH"
    elif base_risk_score >= 5.0:
        risk_level = "MEDIUM"
    
    return {
        "base_risk_score": round(base_risk_score, 1),
        "risk_level": risk_level,
        "confidence": "HIGH" if ai_analysis else "MEDIUM"
    }

# REMOVED LEGACY ENDPOINTS:
# The following endpoints have been removed to clean up the API:
# - /enhance-collection (legacy redirect)
# - /manual-collect (legacy redirect)  
# - /collection-stats (legacy redirect)
# - /test-file-download (legacy redirect)
#
# These caused endpoint duplication and confusion.
# Use the standardized endpoints above instead.