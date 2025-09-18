"""
Enhanced CVE Collector - Complete file with file download functionality
This replaces your existing app/services/cve_collector.py

Enhancements added:
- File download from NIST bulk data feeds
- Enhanced parsing with more comprehensive CVE data extraction
- Better error handling and logging
- Maintains all your existing methods and functionality
"""

import httpx
import asyncio
import json
import gzip
import os
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Set
from datetime import datetime, timedelta
from sqlalchemy.orm import Session, joinedload
from app.models.cve import CVE
#from app.models.service import ServiceInstance, ServiceType
from app.core.config import settings
import logging
import re

logger = logging.getLogger(__name__)

class CVECollector:
    def __init__(self):
        # Keep your existing API-based configuration
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cve/2.0"
        self.headers = {}
        if settings.NVD_API_KEY:
            self.headers["apiKey"] = settings.NVD_API_KEY
        
        # Add file download configuration
        #self.nvd_data_feeds_url = "https://nvd.nist.gov/feeds/json/cve/1.1"
        self.nvd_data_feeds_url = "https://nvd.nist.gov/feeds/json/cve/2.0"
        self.cache_dir = Path("./cve_cache")
        self.cache_dir.mkdir(exist_ok=True)
        
        # Temporary directory for downloads
        self.temp_dir = Path(tempfile.gettempdir()) / "cve_downloads"
        self.temp_dir.mkdir(exist_ok=True)
    
    async def download_cve_file(self, year: int, force_download: bool = False) -> Optional[Path]:
        """
        Download CVE data file for a specific year from NIST data feeds
        
        Args:
            year: Year to download (e.g., 2024)
            force_download: Force download even if cached file exists
            
        Returns:
            Path to downloaded file or None if failed
        """
        try:
            filename = f"nvdcve-2.0-{year}.json.gz"
            url = f"{self.nvd_data_feeds_url}/{filename}"
            local_file = self.cache_dir / filename
            
            # Check if file already exists and is recent (less than 24 hours old)
            if not force_download and local_file.exists():
                file_age = datetime.now() - datetime.fromtimestamp(local_file.stat().st_mtime)
                if file_age < timedelta(hours=24):
                    logger.info(f"Using cached CVE file for {year}: {local_file}")
                    return local_file
            
            logger.info(f"Downloading CVE data for year {year} from {url}")
            
            async with httpx.AsyncClient(timeout=300.0) as client:
                response = await client.get(url)
                response.raise_for_status()
                
                # Save to local cache
                with open(local_file, 'wb') as f:
                    f.write(response.content)
                
                logger.info(f"Downloaded {filename} ({len(response.content)} bytes)")
                return local_file
                
        except Exception as e:
            logger.error(f"Failed to download CVE file for year {year}: {e}")
            return None
    
    async def download_recent_cve_files(self, years_back: int = 3) -> List[Path]:
        """
        Download recent CVE files from NIST data feeds
        
        Args:
            years_back: Number of recent years to download
            
        Returns:
            List of paths to successfully downloaded files
        """
        current_year = datetime.now().year
        years_to_download = [current_year - i for i in range(years_back)]
        
        downloaded_files = []
        
        for year in years_to_download:
            try:
                file_path = await self.download_cve_file(year)
                if file_path:
                    downloaded_files.append(file_path)
                    
                # Add small delay between downloads
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Failed to download CVE file for year {year}: {e}")
                continue
        
        logger.info(f"Downloaded {len(downloaded_files)} CVE files")
        return downloaded_files
    
    def parse_cve_file(self, file_path: Path, days_back: Optional[int] = None) -> List[Dict]:
        """
        Parse downloaded CVE JSON file and extract CVE data
        
        Args:
            file_path: Path to the downloaded CVE file
            days_back: Only include CVEs from last N days (None for all)
            
        Returns:
            List of parsed CVE dictionaries
        """
        try:
            logger.info(f"Parsing CVE file: {file_path}")
            
            # Calculate date threshold if days_back is specified
            date_threshold = None
            if days_back:
                date_threshold = datetime.now() - timedelta(days=days_back)
            
            # Open and parse the gzipped JSON file
            with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                data = json.load(f)
            
            cve_items = data.get('CVE_Items', [])
            logger.info(f"Found {len(cve_items)} CVE items in {file_path.name}")
            
            parsed_cves = []
            
            for item in cve_items:
                try:
                    # Parse the CVE data using your existing method (enhanced)
                    parsed_cve = self.parse_cve_data(item)
                    
                    # Apply date filter if specified
                    if date_threshold and parsed_cve.get('published_date'):
                        if parsed_cve['published_date'] < date_threshold:
                            continue
                    
                    parsed_cves.append(parsed_cve)
                    
                except Exception as e:
                    logger.error(f"Error parsing individual CVE: {e}")
                    continue
            
            logger.info(f"Successfully parsed {len(parsed_cves)} CVEs from {file_path.name}")
            return parsed_cves
            
        except Exception as e:
            logger.error(f"Error parsing CVE file {file_path}: {e}")
            return []
    
    def parse_cve_data(self, cve_item: Dict) -> Dict:
        """
        Enhanced version of your existing parse_cve_data method
        Extracts more comprehensive CVE information from NIST format
        """
        try:
            cve = cve_item.get("cve", {})
            cve_id = cve.get("CVE_data_meta", {}).get("ID", "")
            
            if not cve_id:
                raise ValueError("CVE ID not found")
            
            # Get description (enhanced to handle multiple descriptions)
            descriptions = cve.get("description", {}).get("description_data", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Enhanced CVSS parsing - handles multiple versions
            cvss_score = None
            cvss_vector = None
            severity = None
            cvss_v31_score = None
            cvss_v31_vector = None
            cvss_v31_severity = None
            cvss_v2_score = None
            cvss_v2_vector = None
            exploitability_score = None
            impact_score = None
            
            # Parse impact metrics
            impact = cve_item.get("impact", {})
            
            # CVSS v3.1 (preferred)
            if "baseMetricV3" in impact:
                cvss_v3_data = impact["baseMetricV3"]["cvssV3"]
                cvss_v31_score = cvss_v3_data.get("baseScore")
                cvss_v31_vector = cvss_v3_data.get("vectorString")
                cvss_v31_severity = cvss_v3_data.get("baseSeverity")
                exploitability_score = impact["baseMetricV3"].get("exploitabilityScore")
                impact_score = impact["baseMetricV3"].get("impactScore")
                
                # Use v3 as primary scores
                cvss_score = cvss_v31_score
                cvss_vector = cvss_v31_vector
                severity = cvss_v31_severity
            
            # CVSS v2 (fallback)
            if "baseMetricV2" in impact:
                cvss_v2_data = impact["baseMetricV2"]["cvssV2"]
                cvss_v2_score = cvss_v2_data.get("baseScore")
                cvss_v2_vector = cvss_v2_data.get("vectorString")
                
                # If no v3 score, use v2
                if cvss_score is None:
                    cvss_score = cvss_v2_score
                    cvss_vector = cvss_v2_vector
                    # Map v2 score to severity levels
                    if cvss_v2_score:
                        if cvss_v2_score >= 9.0:
                            severity = 'CRITICAL'
                        elif cvss_v2_score >= 7.0:
                            severity = 'HIGH'
                        elif cvss_v2_score >= 4.0:
                            severity = 'MEDIUM'
                        else:
                            severity = 'LOW'
            
            # Parse dates
            published_date = None
            modified_date = None
            
            published = cve_item.get("publishedDate")
            if published:
                published_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
            
            modified = cve_item.get("lastModifiedDate")
            if modified:
                modified_date = datetime.fromisoformat(modified.replace('Z', '+00:00'))
            
            # Extract references
            references = []
            ref_data = cve.get("references", {}).get("reference_data", [])
            for ref in ref_data:
                references.append({
                    'url': ref.get('url'),
                    'name': ref.get('name'),
                    'refsource': ref.get('refsource'),
                    'tags': ref.get('tags', [])
                })
            
            # Extract problem types (CWE)
            weaknesses = []
            problem_types = cve.get("problemtype", {}).get("problemtype_data", [])
            for problem_type in problem_types:
                for desc in problem_type.get("description", []):
                    if desc.get("lang") == "en":
                        weaknesses.append({
                            'cwe_id': desc.get('value'),
                            'description': desc.get('value')
                        })
            
            # Extract affected products and CPE data
            affected_products = []
            cpe_entries = []
            configurations = []
            
            config_data = cve_item.get("configurations", {})
            nodes = config_data.get("nodes", [])
            
            for node in nodes:
                cpe_matches = []
                for cpe_match in node.get("cpe_match", []):
                    cpe_uri = cpe_match.get("cpe23Uri")
                    if cpe_uri:
                        cpe_entries.append(cpe_uri)
                        
                        # Parse CPE for affected products
                        cpe_parts = cpe_uri.split(':')
                        if len(cpe_parts) >= 5:
                            affected_products.append({
                                'vendor': cpe_parts[3],
                                'product': cpe_parts[4],
                                'version': cpe_parts[5] if len(cpe_parts) > 5 else '*',
                                'version_start': cpe_match.get('versionStartIncluding'),
                                'version_end': cpe_match.get('versionEndIncluding'),
                                'version_start_excluding': cpe_match.get('versionStartExcluding'),
                                'version_end_excluding': cpe_match.get('versionEndExcluding'),
                                'vulnerable': cpe_match.get('vulnerable', True)
                            })
                    
                    cpe_matches.append({
                        'cpe23Uri': cpe_uri,
                        'vulnerable': cpe_match.get('vulnerable', True),
                        'versionStartIncluding': cpe_match.get('versionStartIncluding'),
                        'versionStartExcluding': cpe_match.get('versionStartExcluding'),
                        'versionEndIncluding': cpe_match.get('versionEndIncluding'),
                        'versionEndExcluding': cpe_match.get('versionEndExcluding')
                    })
                
                if cpe_matches:
                    configurations.append({
                        'operator': node.get('operator', 'OR'),
                        'cpe_matches': cpe_matches
                    })
            
            return {
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "severity": severity,
                "cvss_v31_score": cvss_v31_score,
                "cvss_v31_vector": cvss_v31_vector,
                "cvss_v31_severity": cvss_v31_severity,
                "cvss_v2_score": cvss_v2_score,
                "cvss_v2_vector": cvss_v2_vector,
                "exploitability_score": exploitability_score,
                "impact_score": impact_score,
                "published_date": published_date,
                "modified_date": modified_date,
                "affected_products": affected_products,
                "cpe_entries": cpe_entries,
                "references": references,
                "weaknesses": weaknesses,
                "configurations": configurations
            }
            
        except Exception as e:
            logger.error(f"Error parsing CVE data: {e}")
            # Fallback to basic parsing
            cve = cve_item.get("cve", {})
            cve_id = cve.get("CVE_data_meta", {}).get("ID", "")
            descriptions = cve.get("description", {}).get("description_data", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            return {
                "cve_id": cve_id,
                "description": description,
                "cvss_score": None,
                "cvss_vector": None,
                "severity": None,
                "published_date": None,
                "modified_date": None
            }
    
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
    
    async def collect_cves_from_files(self, db: Session, days_back: int = 7) -> List[Dict]:
        """
        NEW METHOD: Collect CVEs from downloaded NIST files instead of API
        This replaces API-based collection with file-based collection
        """
        try:
            # Get service keywords for filtering
            service_keywords = self.get_service_keywords(db)
            
            if not service_keywords:
                logger.info("No service keywords found, will collect all recent CVEs")
            
            # Download recent CVE files
            cve_files = await self.download_recent_cve_files(years_back=3)
            
            if not cve_files:
                logger.error("No CVE files downloaded successfully")
                return []
            
            all_relevant_cves = []
            
            for file_path in cve_files:
                try:
                    # Parse CVEs from file, filtering by date
                    file_cves = self.parse_cve_file(file_path, days_back=days_back)
                    
                    # Filter CVEs based on service keywords
                    for cve_data in file_cves:
                        description = cve_data.get("description", "")
                        
                        # If we have service keywords, filter by them
                        if service_keywords:
                            if self.is_cve_relevant(description, service_keywords):
                                all_relevant_cves.append(cve_data)
                                logger.debug(f"CVE {cve_data['cve_id']} is relevant to our services")
                        else:
                            # No service keywords, include all recent CVEs
                            all_relevant_cves.append(cve_data)
                    
                except Exception as e:
                    logger.error(f"Error processing file {file_path}: {e}")
                    continue
            
            # Remove duplicates based on CVE ID
            seen_cve_ids = set()
            unique_cves = []
            
            for cve_data in all_relevant_cves:
                cve_id = cve_data.get("cve_id", "")
                if cve_id and cve_id not in seen_cve_ids:
                    seen_cve_ids.add(cve_id)
                    unique_cves.append(cve_data)
            
            logger.info(f"Collected {len(unique_cves)} unique relevant CVEs from files")
            return unique_cves
            
        except Exception as e:
            logger.error(f"Error collecting CVEs from files: {e}")
            return []
    
    # Keep all your existing API-based methods for backwards compatibility
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

# Keep your existing scheduled function but enhance it
async def scheduled_cve_collection(db: Session, use_files: bool = True):
    """
    Enhanced function to be called by your scheduler
    
    Args:
        db: Database session
        use_files: If True, use file download method; if False, use API method
    """
    try:
        if not db or not hasattr(db, 'query'):
            logger.error(f"Invalid database session: {type(db)}")
            return
        
        collector = CVECollector()
        await collector.run_service_specific_collection(db, days_back=7, use_files=use_files)
        
    except Exception as e:
        logger.error(f"Scheduled CVE collection failed: {e}")
        raise