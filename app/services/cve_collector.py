import httpx
import asyncio
from typing import List, Dict, Optional, Set
from datetime import datetime, timedelta
from sqlalchemy.orm import Session, joinedload
from app.models.cve import CVE
from app.models.service import ServiceInstance, ServiceType
from app.core.config import settings
import logging
import re

logger = logging.getLogger(__name__)

class CVECollector:
    def __init__(self):
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {}
        if settings.NVD_API_KEY:
            self.headers["apiKey"] = settings.NVD_API_KEY
    
    def get_service_keywords(self, db: Session) -> Set[str]:
        """Extract keywords from service instances to filter CVEs"""
        try:
            # Validate that db is a proper Session object
            if not hasattr(db, 'query'):
                logger.error(f"Invalid database session object: {type(db)}")
                raise ValueError(f"Expected SQLAlchemy Session, got {type(db)}")
            
            # Get all active service instances with their types
            service_instances = db.query(ServiceInstance).options(
                joinedload(ServiceInstance.service_type)
            ).filter(ServiceInstance.status == "active").all()
            
            if not service_instances:
                logger.info("No active service instances found in database")
                return set()
            
            keywords = set()
            
            for instance in service_instances:
                # Add service type name
                if instance.service_type and instance.service_type.name:
                    keywords.add(instance.service_type.name.lower())
                
                # Add vendor if available
                if instance.service_type and instance.service_type.vendor:
                    keywords.add(instance.service_type.vendor.lower())
                
                # Add instance name (might contain product info)
                if instance.name:
                    # Extract meaningful words from instance name
                    name_words = re.findall(r'\b[a-zA-Z]{3,}\b', instance.name.lower())
                    keywords.update(name_words)
                
                # Add version if specified (for version-specific CVEs)
                if instance.version:
                    version_words = re.findall(r'\b[a-zA-Z]{3,}\b', instance.version.lower())
                    keywords.update(version_words)
            
            # Remove common generic words that won't help with CVE filtering
            generic_words = {'server', 'service', 'instance', 'production', 'staging', 
                            'development', 'prod', 'dev', 'test', 'system', 'application'}
            keywords = keywords - generic_words
            
            logger.info(f"Extracted {len(keywords)} keywords from {len(service_instances)} service instances")
            logger.debug(f"Keywords: {', '.join(sorted(keywords))}")
            
            return keywords
            
        except Exception as e:
            logger.error(f"Error extracting service keywords: {e}")
            return set()
    
    def is_cve_relevant(self, cve_description: str, keywords: Set[str]) -> bool:
        """Check if CVE description mentions any of our service keywords"""
        if not keywords:
            return False
        
        description_lower = cve_description.lower()
        
        # Check if any keyword appears in the description
        for keyword in keywords:
            if keyword in description_lower:
                return True
        
        return False
    
    async def collect_recent_cves(self, db: Session, days_back: int = 7) -> List[Dict]:
        """Collect CVEs from the last N days, filtered by service instances in database"""
        
        try:
            # Validate database session
            if not hasattr(db, 'query'):
                logger.error(f"Invalid database session object: {type(db)}")
                return []
            
            # First, check if we have any service instances
            service_keywords = self.get_service_keywords(db)
            
            if not service_keywords:
                logger.info("No service instances found in database. Skipping CVE collection.")
                return []
            
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            
            params = {
                "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": 100
            }
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    self.nvd_base_url,
                    params=params,
                    headers=self.headers
                )
                response.raise_for_status()
                
                data = response.json()
                all_vulnerabilities = data.get("vulnerabilities", [])
                
                # Filter CVEs based on service keywords
                relevant_vulnerabilities = []
                
                for vuln in all_vulnerabilities:
                    cve_data = self.parse_cve_data(vuln)
                    description = cve_data.get("description", "")
                    
                    if self.is_cve_relevant(description, service_keywords):
                        relevant_vulnerabilities.append(vuln)
                        logger.debug(f"CVE {cve_data['cve_id']} is relevant to our services")
                
                logger.info(f"Filtered {len(relevant_vulnerabilities)} relevant CVEs from {len(all_vulnerabilities)} total CVEs")
                return relevant_vulnerabilities
                
        except Exception as e:
            logger.error(f"CVE collection error: {e}")
            return []
    
    async def collect_cves_for_specific_services(self, db: Session, service_names: List[str], days_back: int = 30) -> List[Dict]:
        """Collect CVEs for specific service names/products"""
        
        if not service_names:
            logger.info("No service names provided. Skipping CVE collection.")
            return []
        
        all_relevant_cves = []
        
        for service_name in service_names:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            
            # Search for CVEs mentioning the specific service
            params = {
                "keywordSearch": service_name,
                "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": 50
            }
            
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(
                        self.nvd_base_url,
                        params=params,
                        headers=self.headers
                    )
                    response.raise_for_status()
                    
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    
                    logger.info(f"Found {len(vulnerabilities)} CVEs for service: {service_name}")
                    all_relevant_cves.extend(vulnerabilities)
                    
            except Exception as e:
                logger.error(f"CVE collection error for service {service_name}: {e}")
        
        # Remove duplicates based on CVE ID
        seen_cve_ids = set()
        unique_cves = []
        
        for vuln in all_relevant_cves:
            cve_id = vuln.get("cve", {}).get("id", "")
            if cve_id and cve_id not in seen_cve_ids:
                seen_cve_ids.add(cve_id)
                unique_cves.append(vuln)
        
        logger.info(f"Total unique CVEs found: {len(unique_cves)}")
        return unique_cves
    
    def parse_cve_data(self, cve_item: Dict) -> Dict:
        """Parse CVE data from NVD format"""
        cve = cve_item.get("cve", {})
        cve_id = cve.get("id", "")
        
        # Get description
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Get CVSS score
        cvss_score = None
        cvss_vector = None
        severity = None
        
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity")
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
        
        # Parse dates
        published = cve.get("published")
        modified = cve.get("lastModified")
        
        published_date = None
        modified_date = None
        
        if published:
            published_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
        if modified:
            modified_date = datetime.fromisoformat(modified.replace('Z', '+00:00'))
        
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity,
            "published_date": published_date,
            "modified_date": modified_date
        }
    
    async def store_cves(self, db: Session, cve_data_list: List[Dict]):
        """Store CVEs in database"""
        if not cve_data_list:
            logger.info("No CVEs to store")
            return
        
        stored_count = 0
        updated_count = 0
        
        for cve_data in cve_data_list:
            try:
                # Check if CVE already exists
                existing = db.query(CVE).filter(CVE.cve_id == cve_data["cve_id"]).first()
                
                if not existing:
                    new_cve = CVE(**cve_data)
                    db.add(new_cve)
                    stored_count += 1
                else:
                    # Update existing CVE if modified
                    if cve_data.get("modified_date") and existing.modified_date:
                        if cve_data["modified_date"] > existing.modified_date:
                            for key, value in cve_data.items():
                                setattr(existing, key, value)
                            existing.processed = False  # Mark for reprocessing
                            updated_count += 1
            
            except Exception as e:
                logger.error(f"Error storing CVE {cve_data.get('cve_id', '')}: {e}")
        
        try:
            db.commit()
            logger.info(f"Stored {stored_count} new CVEs and updated {updated_count} existing CVEs")
        except Exception as e:
            logger.error(f"Database commit error: {e}")
            db.rollback()
    
    async def run_service_specific_collection(self, db: Session, days_back: int = 7):
        """Main method to run CVE collection based on services in database"""
        try:
            # Validate database session first
            if not hasattr(db, 'query'):
                logger.error(f"Invalid database session object: {type(db)}. Expected SQLAlchemy Session.")
                raise ValueError(f"Expected SQLAlchemy Session, got {type(db)}")
            
            logger.info("Starting service-specific CVE collection")
            
            # Method 1: Collect recent CVEs and filter by service keywords
            recent_cves = await self.collect_recent_cves(db, days_back)
            
            if recent_cves:
                # Parse and store the relevant CVEs
                parsed_cves = []
                for cve_item in recent_cves:
                    parsed_cve = self.parse_cve_data(cve_item)
                    parsed_cves.append(parsed_cve)
                
                await self.store_cves(db, parsed_cves)
            
            # Method 2: Optionally, also search specifically for service names
            try:
                service_instances = db.query(ServiceInstance).options(
                    joinedload(ServiceInstance.service_type)
                ).filter(ServiceInstance.status == "active").all()
                
                if service_instances:
                    # Extract unique service type names for targeted searches
                    service_names = set()
                    for instance in service_instances:
                        if instance.service_type and instance.service_type.name:
                            service_names.add(instance.service_type.name)
                        if instance.service_type and instance.service_type.vendor:
                            service_names.add(instance.service_type.vendor)
                    
                    # Limit to avoid too many API calls
                    service_names = list(service_names)[:5]  # Top 5 most common services
                    
                    if service_names:
                        specific_cves = await self.collect_cves_for_specific_services(db, service_names, days_back)
                        
                        if specific_cves:
                            parsed_specific_cves = []
                            for cve_item in specific_cves:
                                parsed_cve = self.parse_cve_data(cve_item)
                                parsed_specific_cves.append(parsed_cve)
                            
                            await self.store_cves(db, parsed_specific_cves)
                            
            except Exception as e:
                logger.error(f"Error in specific service CVE collection: {e}")
            
            logger.info("CVE collection completed")
            
        except Exception as e:
            logger.error(f"CVE collection failed: {e}")
            raise


# Usage example with proper error handling:
async def scheduled_cve_collection(db: Session):
    """Function to be called by your scheduler"""
    try:
        if not db or not hasattr(db, 'query'):
            logger.error(f"Invalid database session: {type(db)}")
            return
        
        collector = CVECollector()
        await collector.run_service_specific_collection(db, days_back=7)
        
    except Exception as e:
        logger.error(f"Scheduled CVE collection failed: {e}")
        raise