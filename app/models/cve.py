from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.core.database import Base

class CVE(Base):
    """Enhanced CVE model with CPE correlation support"""
    __tablename__ = "cves"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(20), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=False)
    cvss_score = Column(Float, nullable=True, index=True)
    cvss_vector = Column(String(200), nullable=True)
    published_date = Column(DateTime, nullable=True, index=True)
    modified_date = Column(DateTime, nullable=True, index=True)
    severity = Column(String(20), nullable=True, index=True)
    
    # Enhanced fields for better correlation
    affected_products = Column(JSON, nullable=True)  # List of {vendor, product, version_start, version_end}
    cpe_entries = Column(JSON, nullable=True)  # CPE 2.3 identifiers
    references = Column(JSON, nullable=True)  # External references
    weaknesses = Column(JSON, nullable=True)  # CWE information
    configurations = Column(JSON, nullable=True)  # Vulnerable configurations
    
    # CVSS v3.1 details
    cvss_v31_score = Column(Float, nullable=True)
    cvss_v31_vector = Column(String(200), nullable=True)
    cvss_v31_severity = Column(String(20), nullable=True)
    
    # CVSS v2 details (for legacy support)
    cvss_v2_score = Column(Float, nullable=True)
    cvss_v2_vector = Column(String(200), nullable=True)
    
    # Exploitability and impact metrics
    exploitability_score = Column(Float, nullable=True)
    impact_score = Column(Float, nullable=True)
    
    # AI-generated fields
    ai_risk_score = Column(Float, nullable=True, index=True)
    ai_summary = Column(Text, nullable=True)
    mitigation_suggestions = Column(JSON, nullable=True)  # Structured suggestions
    detection_methods = Column(JSON, nullable=True)  # Detection methods
    upgrade_paths = Column(JSON, nullable=True)  # Upgrade recommendations
    
    # Correlation fields
    affects_service_types = Column(JSON, nullable=True)  # Matched service type IDs
    correlation_confidence = Column(Float, nullable=True, index=True)  # Confidence score 0-1
    correlation_method = Column(String(50), nullable=True)  # How it was matched
    
    # Processing status
    processed = Column(Boolean, default=False, index=True)
    processing_errors = Column(JSON, nullable=True)  # Any processing errors
    last_processed = Column(DateTime, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    def get_primary_cvss_score(self):
        """Get the primary CVSS score (prefer v3.1, then v3.0, then v2)"""
        return self.cvss_v31_score or self.cvss_score or self.cvss_v2_score
    
    def get_primary_severity(self):
        """Get the primary severity (prefer v3.1, then base severity)"""
        return self.cvss_v31_severity or self.severity
    
    def get_affected_vendors(self):
        """Extract unique vendors from affected products"""
        if not self.affected_products:
            return []
        
        vendors = set()
        for product in self.affected_products:
            if isinstance(product, dict) and 'vendor' in product:
                vendors.add(product['vendor'])
        
        return sorted(list(vendors))
    
    def get_affected_products_list(self):
        """Extract unique products from affected products"""
        if not self.affected_products:
            return []
        
        products = set()
        for product in self.affected_products:
            if isinstance(product, dict) and 'product' in product:
                products.add(product['product'])
        
        return sorted(list(products))
    
    def is_recent(self, days=30):
        """Check if CVE was published in the last N days"""
        if not self.published_date:
            return False
        
        from datetime import datetime, timedelta
        cutoff = datetime.now() - timedelta(days=days)
        return self.published_date >= cutoff
    
    def is_high_severity(self):
        """Check if CVE is high or critical severity"""
        severity = self.get_primary_severity()
        if severity:
            return severity.upper() in ['HIGH', 'CRITICAL']
        
        score = self.get_primary_cvss_score()
        if score:
            return score >= 7.0
        
        return False
    
    def get_cpe_vendors_products(self):
        """Extract vendor/product pairs from CPE entries"""
        if not self.cpe_entries:
            return []
        
        vendor_products = []
        for cpe in self.cpe_entries:
            if isinstance(cpe, str):
                # Parse CPE string: cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(':')
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    if vendor != '*' and product != '*':
                        vendor_products.append((vendor, product))
        
        return list(set(vendor_products))  # Remove duplicates

class CVEThreatIntelligence(Base):
    """Additional threat intelligence for CVEs"""
    __tablename__ = "cve_threat_intelligence"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(20), ForeignKey("cves.cve_id"), nullable=False, unique=True)
    
    # Exploitation status
    exploited_in_wild = Column(Boolean, nullable=True, index=True)
    exploit_available = Column(Boolean, nullable=True, index=True)
    exploit_complexity = Column(String(20), nullable=True)  # Low, Medium, High
    
    # Intelligence sources
    intelligence_sources = Column(JSON, nullable=True)  # List of source names
    intelligence_last_updated = Column(DateTime, nullable=True)
    
    # CISA KEV (Known Exploited Vulnerabilities)
    in_cisa_kev = Column(Boolean, default=False, index=True)
    cisa_kev_date_added = Column(DateTime, nullable=True)
    cisa_kev_due_date = Column(DateTime, nullable=True)
    cisa_kev_notes = Column(Text, nullable=True)
    
    # EPSS (Exploit Prediction Scoring System)
    epss_score = Column(Float, nullable=True, index=True)
    epss_percentile = Column(Float, nullable=True)
    epss_last_updated = Column(DateTime, nullable=True)
    
    # Social media and news mentions
    social_mentions = Column(Integer, default=0)
    news_mentions = Column(Integer, default=0)
    trending_score = Column(Float, nullable=True)
    
    # Patch availability
    patch_available = Column(Boolean, nullable=True)
    patch_release_date = Column(DateTime, nullable=True)
    patch_sources = Column(JSON, nullable=True)  # Links to patches
    
    # Workarounds
    workarounds_available = Column(Boolean, nullable=True)
    workaround_details = Column(JSON, nullable=True)
    
    # Risk assessment
    business_risk_score = Column(Float, nullable=True)
    technical_risk_score = Column(Float, nullable=True)
    
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Relationship
    cve = relationship("CVE", backref="threat_intelligence")

class CVETagging(Base):
    """Flexible tagging system for CVEs"""
    __tablename__ = "cve_tagging"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(20), ForeignKey("cves.cve_id"), nullable=False)
    tag = Column(String(100), nullable=False, index=True)
    tag_category = Column(String(50), nullable=True, index=True)  # e.g., 'technology', 'impact', 'custom'
    
    # Tag metadata
    added_by = Column(String(100), nullable=True)
    confidence = Column(Float, default=1.0)  # Confidence in tag accuracy
    source = Column(String(50), nullable=True)  # 'manual', 'ai', 'automated'
    
    created_at = Column(DateTime, server_default=func.now())
    
    # Composite index for performance
    __table_args__ = (
        {'mysql_charset': 'utf8mb4'},
    )
    
    # Relationship
    cve = relationship("CVE", backref="tags")