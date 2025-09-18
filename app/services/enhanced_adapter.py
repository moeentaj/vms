import json
import logging
from typing import Dict, List, Optional, Any
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from app.models.cve import CVE
from app.models.service import ServiceInstance, ServiceType
from app.services.cve_collector import CVECollector  # Your existing collector
from app.services.ai_agent import LocalAIAgent  # Your existing AI agent

logger = logging.getLogger(__name__)

class EnhancedCVEAdapter:
    """
    Adapter to enhance your existing CVE collector with correlation features
    without requiring immediate full replacement
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.cve_collector = CVECollector()
        self.ai_agent = LocalAIAgent()
    
    async def collect_and_enhance_cves(self, days_back: int = 7) -> Dict[str, Any]:
        """
        Use your existing CVE collector but enhance the stored data
        """
        stats = {
            'collected': 0,
            'enhanced': 0,
            'correlated': 0,
            'errors': 0
        }
        
        try:
            # Use your existing collection method
            await self.cve_collector.run_service_specific_collection(self.db, days_back)
            
            # Get newly collected CVEs that need enhancement
            unprocessed_cves = self.db.query(CVE).filter(
                CVE.processed == False
            ).all()
            
            for cve in unprocessed_cves:
                try:
                    # Enhance CVE data with correlation fields
                    await self._enhance_cve_data(cve)
                    stats['enhanced'] += 1
                    
                    # Run basic correlation
                    correlations = await self._run_basic_correlation(cve)
                    if correlations:
                        stats['correlated'] += 1
                    
                except Exception as e:
                    logger.error(f"Error enhancing CVE {cve.cve_id}: {e}")
                    stats['errors'] += 1
            
            self.db.commit()
            stats['collected'] = len(unprocessed_cves)
            
        except Exception as e:
            logger.error(f"CVE collection and enhancement failed: {e}")
            stats['errors'] += 1
        
        return stats
    
    async def _enhance_cve_data(self, cve: CVE) -> None:
        """
        Enhance existing CVE with additional fields for correlation
        """
        try:
            # Extract product information from description if not already present
            if not cve.affected_products:
                products = self._extract_products_from_description(cve.description)
                if products:
                    cve.affected_products = json.dumps(products)
            
            # Generate CPE entries if possible
            if not cve.cpe_entries and cve.affected_products:
                cpe_entries = self._generate_cpe_entries(cve.affected_products)
                if cpe_entries:
                    cve.cpe_entries = json.dumps(cpe_entries)
            
            # Use your existing AI agent for analysis
            if not cve.ai_summary:
                analysis = await self.ai_agent.analyze_cve(cve.description, cve.cve_id)
                if analysis:
                    cve.ai_risk_score = analysis.get('risk_score')
                    cve.ai_summary = analysis.get('summary')
                    cve.mitigation_suggestions = json.dumps(analysis.get('mitigations', []))
                    cve.detection_methods = json.dumps(analysis.get('detection_methods', []))
                    cve.upgrade_paths = json.dumps(analysis.get('upgrade_paths', []))
            
            # Mark as processed
            cve.processed = True
            
        except Exception as e:
            logger.error(f"Error enhancing CVE {cve.cve_id}: {e}")
    
    def _extract_products_from_description(self, description: str) -> List[Dict[str, str]]:
        """
        Extract product information from CVE description using pattern matching
        """
        products = []
        description_lower = description.lower()
        
        # Common product patterns
        product_patterns = [
            # Apache products
            (r'apache\s+(\w+)', 'Apache Software Foundation'),
            # Microsoft products
            (r'microsoft\s+(\w+)', 'Microsoft'),
            # Oracle products
            (r'oracle\s+(\w+)', 'Oracle'),
            # MySQL
            (r'mysql', 'Oracle'),
            # PostgreSQL
            (r'postgresql', 'PostgreSQL Global Development Group'),
            # Nginx
            (r'nginx', 'Nginx Inc.'),
            # Docker
            (r'docker', 'Docker Inc.'),
            # Kubernetes
            (r'kubernetes', 'Kubernetes'),
        ]
        
        import re
        for pattern, vendor in product_patterns:
            matches = re.findall(pattern, description_lower)
            for match in matches:
                product_name = match if isinstance(match, str) else ' '.join(match)
                products.append({
                    'vendor': vendor,
                    'product': product_name,
                    'source': 'description_extraction'
                })
        
        return products[:5]  # Limit to 5 products
    
    def _generate_cpe_entries(self, affected_products: str) -> List[str]:
        """
        Generate basic CPE entries from product information
        """
        cpe_entries = []
        
        try:
            products = json.loads(affected_products) if isinstance(affected_products, str) else affected_products
            
            for product in products:
                vendor = product.get('vendor', '').lower().replace(' ', '_')
                product_name = product.get('product', '').lower().replace(' ', '_')
                
                if vendor and product_name:
                    # Generate basic CPE 2.3 format
                    cpe = f"cpe:2.3:a:{vendor}:{product_name}:*:*:*:*:*:*:*:*"
                    cpe_entries.append(cpe)
        
        except Exception as e:
            logger.error(f"Error generating CPE entries: {e}")
        
        return cpe_entries
    
    async def _run_basic_correlation(self, cve: CVE) -> List[Dict[str, Any]]:
        """
        Run basic correlation without the full correlation engine
        """
        correlations = []
        
        try:
            # Simple correlation based on service types and keywords
            if cve.affected_products:
                products = json.loads(cve.affected_products)
                
                for product in products:
                    vendor = product.get('vendor', '').lower()
                    product_name = product.get('product', '').lower()
                    
                    # Find matching service instances
                    matching_services = self.db.query(ServiceInstance).join(ServiceType).filter(
                        or_(
                            ServiceType.vendor.ilike(f"%{vendor}%"),
                            ServiceType.name.ilike(f"%{product_name}%"),
                            ServiceType.product_name.ilike(f"%{product_name}%")
                        )
                    ).all()
                    
                    for service in matching_services:
                        confidence = self._calculate_basic_confidence(product, service)
                        
                        if confidence > 0.5:  # Basic threshold
                            correlation = {
                                'service_instance_id': service.id,
                                'confidence_score': confidence,
                                'method': 'basic_product_match',
                                'product_info': product
                            }
                            correlations.append(correlation)
            
            # Store basic correlation info in CVE
            if correlations:
                service_ids = [c['service_instance_id'] for c in correlations]
                cve.affects_service_types = json.dumps(service_ids)
                cve.correlation_confidence = max([c['confidence_score'] for c in correlations])
                cve.correlation_method = 'basic_adapter'
        
        except Exception as e:
            logger.error(f"Error in basic correlation for {cve.cve_id}: {e}")
        
        return correlations
    
    def _calculate_basic_confidence(self, product: Dict[str, str], service: ServiceInstance) -> float:
        """
        Calculate basic confidence score for correlation
        """
        confidence = 0.0
        
        vendor = product.get('vendor', '').lower()
        product_name = product.get('product', '').lower()
        
        # Vendor matching
        if service.service_type.vendor:
            if vendor in service.service_type.vendor.lower():
                confidence += 0.4
        
        # Product name matching
        if service.service_type.name:
            if product_name in service.service_type.name.lower():
                confidence += 0.4
        
        if service.service_type.product_name:
            if product_name in service.service_type.product_name.lower():
                confidence += 0.4
        
        # Service instance name matching
        if service.name:
            if product_name in service.name.lower():
                confidence += 0.2
        
        return min(confidence, 1.0)
    
    async def analyze_cve_with_existing_agent(self, cve_id: str) -> Dict[str, Any]:
        """
        Use your existing AI agent to analyze a CVE
        """
        cve = self.db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if not cve:
            raise ValueError(f"CVE {cve_id} not found")
        
        # Use your existing AI agent
        analysis = await self.ai_agent.analyze_cve(cve.description, cve.cve_id)
        
        # Store the analysis
        if analysis:
            cve.ai_risk_score = analysis.get('risk_score')
            cve.ai_summary = analysis.get('summary')
            cve.mitigation_suggestions = json.dumps(analysis.get('mitigations', []))
            cve.detection_methods = json.dumps(analysis.get('detection_methods', []))
            cve.upgrade_paths = json.dumps(analysis.get('upgrade_paths', []))
            cve.processed = True
            
            self.db.commit()
        
        return {
            'cve_id': cve_id,
            'analysis': analysis,
            'message': 'CVE analysis completed using existing AI agent'
        }
    
    def get_enhanced_cve_stats(self) -> Dict[str, Any]:
        """
        Get statistics about enhanced CVE data
        """
        total_cves = self.db.query(CVE).count()
        processed_cves = self.db.query(CVE).filter(CVE.processed == True).count()
        ai_analyzed = self.db.query(CVE).filter(CVE.ai_risk_score.isnot(None)).count()
        correlated = self.db.query(CVE).filter(CVE.correlation_confidence.isnot(None)).count()
        
        return {
            'total_cves': total_cves,
            'processed_cves': processed_cves,
            'ai_analyzed': ai_analyzed,
            'correlated': correlated,
            'processing_rate': (processed_cves / total_cves * 100) if total_cves > 0 else 0,
            'correlation_rate': (correlated / total_cves * 100) if total_cves > 0 else 0
        }

# Enhanced API endpoints that work with your existing system
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User

# Add these endpoints to your existing cves.py file
def add_enhanced_endpoints(router: APIRouter):
    """
    Add these endpoints to your existing CVE router
    """
    
    @router.post("/enhance-collection")
    async def enhanced_cve_collection(
        background_tasks: BackgroundTasks,
        days_back: int = 7,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        """Enhanced CVE collection using existing services"""
        if current_user.role not in ["admin", "manager"]:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        background_tasks.add_task(run_enhanced_collection_task, days_back)
        return {"message": f"Enhanced CVE collection started for last {days_back} days"}
    
    @router.get("/enhanced-stats")
    async def get_enhanced_stats(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        """Get enhanced CVE statistics"""
        adapter = EnhancedCVEAdapter(db)
        return adapter.get_enhanced_cve_stats()
    
    @router.post("/{cve_id}/enhanced-analyze")
    async def enhanced_analyze_cve(
        cve_id: str,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        """Analyze CVE using existing AI agent with enhancements"""
        adapter = EnhancedCVEAdapter(db)
        try:
            result = await adapter.analyze_cve_with_existing_agent(cve_id)
            return result
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            logger.error(f"Enhanced CVE analysis failed for {cve_id}: {e}")
            raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

async def run_enhanced_collection_task(days_back: int):
    """Background task for enhanced CVE collection"""
    from app.core.database import SessionLocal
    
    db = SessionLocal()
    try:
        adapter = EnhancedCVEAdapter(db)
        stats = await adapter.collect_and_enhance_cves(days_back)
        logger.info(f"Enhanced CVE collection completed: {stats}")
    except Exception as e:
        logger.error(f"Enhanced CVE collection failed: {e}")
    finally:
        db.close()