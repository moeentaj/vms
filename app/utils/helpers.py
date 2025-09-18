from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import hashlib
import secrets

def generate_api_key() -> str:
    """Generate a secure API key"""
    return secrets.token_urlsafe(32)

def hash_data(data: str) -> str:
    """Hash data using SHA-256"""
    return hashlib.sha256(data.encode()).hexdigest()

def calculate_risk_score(cvss_score: float, asset_criticality: str, environment: str) -> float:
    """Calculate combined risk score"""
    
    # Base CVSS score
    base_score = cvss_score or 5.0
    
    # Criticality multiplier
    criticality_multipliers = {
        "low": 0.7,
        "medium": 1.0,
        "high": 1.3,
        "critical": 1.6
    }
    
    # Environment multiplier
    environment_multipliers = {
        "development": 0.5,
        "staging": 0.8,
        "production": 1.5
    }
    
    crit_mult = criticality_multipliers.get(asset_criticality.lower(), 1.0)
    env_mult = environment_multipliers.get(environment.lower(), 1.0)
    
    # Calculate final score (max 10.0)
    risk_score = min(base_score * crit_mult * env_mult, 10.0)
    
    return round(risk_score, 2)

def format_datetime(dt: Optional[datetime]) -> Optional[str]:
    """Format datetime for API responses"""
    if dt:
        return dt.isoformat()
    return None

def parse_tags(tags_string: Optional[str]) -> List[str]:
    """Parse comma-separated tags string"""
    if not tags_string:
        return []
    
    return [tag.strip() for tag in tags_string.split(",") if tag.strip()]

def validate_cve_id(cve_id: str) -> bool:
    """Validate CVE ID format"""
    import re
    pattern = r'^CVE-\d{4}-\d{4,}'