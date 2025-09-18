# app/services/monitoring.py
import logging
from datetime import datetime, timedelta
from app.core.database import SessionLocal
from app.models.cve import CVE

logger = logging.getLogger(__name__)

def check_correlation_health():
    """Monitor correlation system health"""
    db = SessionLocal()
    
    try:
        # Check recent CVEs
        yesterday = datetime.utcnow() - timedelta(days=1)
        recent_cves = db.query(CVE).filter(
            CVE.created_at >= yesterday
        ).count()
        
        correlated_recent = db.query(CVE).filter(
            CVE.created_at >= yesterday,
            CVE.correlation_confidence.isnot(None)
        ).count()
        
        correlation_rate = (correlated_recent / recent_cves * 100) if recent_cves > 0 else 0
        
        # Alert if correlation rate is too low
        if correlation_rate < 70:  # 70% threshold
            logger.warning(f"Low correlation rate: {correlation_rate:.1f}% for recent CVEs")
        
        # Check for stale CVEs (not processed within 2 hours)
        two_hours_ago = datetime.utcnow() - timedelta(hours=2)
        stale_cves = db.query(CVE).filter(
            CVE.created_at <= two_hours_ago,
            CVE.processed == False
        ).count()
        
        if stale_cves > 0:
            logger.warning(f"Found {stale_cves} stale unprocessed CVEs")
        
        return {
            'recent_cves': recent_cves,
            'correlation_rate': correlation_rate,
            'stale_cves': stale_cves,
            'status': 'healthy' if correlation_rate >= 70 and stale_cves == 0 else 'degraded'
        }
        
    finally:
        db.close()