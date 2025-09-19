"""
Cleaned CVE Collector - Asset-Based Architecture Focus
app/services/cve_collector.py

This replaces the existing collector with a clean, asset-focused implementation.
Removes all service-based dependencies and focuses on:
- Asset-based CVE relevance filtering
- CPE-based correlation preparation  
- File download and API collection methods
- Clean, maintainable code structure
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
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from app.models.cve import CVE
from app.models.asset import Asset  # Asset-only import
from app.core.config import settings
import logging
import re

logger = logging.getLogger(__name__)

class CVECollector:
    """Asset-focused CVE collector with CPE correlation support"""
    
    def __init__(self):
        # NVD API configuration
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cve/2.0"
        self.headers = {}
        if settings.NVD_API_KEY:
            self.headers["apiKey"] = settings.NVD_API_KEY
        
        # File download configuration
        self.nvd_data_feeds_url = "https://nvd.nist.gov/feeds/json/cve/2.0"
        self.cache_dir = Path("./cve_cache")
        self.cache_dir.mkdir(exist_ok=True)
        
        # Rate limiting
        self.requests_per_second = settings.NIST_RATE_LIMIT_WITH_KEY if settings.NVD_API_KEY else settings.NIST_RATE_LIMIT_WITHOUT_KEY
        self.request_delay = 1.0 / self.requests_per_second if self.requests_per_second > 0 else 2.0
        
    async def download_cve_file(self, year: int, force_download: bool = False) -> Optional[Path]:
        """Download CVE data file for a specific year from NIST data feeds"""
        try:
            filename = f"nvdcve-2.0-{year}.json.gz"
            url = f"{self.nvd_data_feeds_url}/{filename}"
            local_file = self.cache_dir / filename
            
            # Check if file already exists and is recent (less than 24 hours old)
            if not force_download and local_file.exists():
                file_age = datetime.now() - datetime.fromtimestamp(local_file.stat().st_mtime)
                if file_age < timedelta(hours=24):
                    logger.info(f"Using cached CVE file: {filename} (age: {file_age})")
                    return local_file
            
            logger.info(f"Downloading CVE data for {year} from {url}")
            
            async with httpx.AsyncClient(timeout=300.0) as client:
                response = await client.get(url)
                response.raise_for_status()
                
                # Write to local cache
                with open(local_file, 'wb') as f:
                    f.write(response.content)
                
                logger.info(f"Downloaded {filename} ({len(response.content):,} bytes)")
                return local_file
                
        except Exception as e:
            logger.error(f"Failed to download CVE file for year {year}: {e}")
            return None
    
    async def download_recent_cve_files(self, years_back: int = 3) -> List[Path]:
        """Download CVE files for recent years"""
        current_year = datetime.now().year
        downloaded_files = []
        
        for year in range(current_year, current_year - years_back, -1):
            file_path = await self.download_cve_file(year)
            if file_path:
                downloaded_files.append(file_path)
        
        logger.info(f"Downloaded {len(downloaded_files)} CVE files")
        return downloaded_files
    
    def parse_cve_file(self, file_path: Path, days_back: int = 7) -> List[Dict]:
        """Parse a gzipped CVE JSON file and filter by date"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_back)
            cves = []
            
            logger.info(f"Parsing CVE file: {file_path}")
            
            with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                data = json.load(f)
                
                vulnerabilities = data.get('vulnerabilities', [])
                logger.info(f"Found {len(vulnerabilities)} total CVEs in file")
                
                for vuln_data in vulnerabilities:
                    cve_item = vuln_data.get('cve', {})
                    
                    # Extract basic CVE information
                    cve_id = cve_item.get('id', '')
                    if not cve_id:
                        continue
                    
                    # Check publish date for filtering
                    published_str = cve_item.get('published', '')
                    if published_str:
                        try:
                            published_date = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                            if published_date.replace(tzinfo=None) < cutoff_date:
                                continue  # Skip old CVEs
                        except Exception as e:
                            logger.debug(f"Could not parse date for {cve_id}: {e}")
                            continue
                    
                    # Extract description
                    descriptions = cve_item.get('descriptions', [])
                    description = ''
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    # Extract CVSS scores and severity
                    cvss_data = self._extract_cvss_data(cve_item)
                    
                    # Extract CPE information
                    affected_products = self._extract_affected_products(cve_item)
                    cpe_entries = self._extract_cpe_entries(cve_item)
                    
                    cve_data = {
                        'cve_id': cve_id,
                        'description': description,
                        'published_date': published_str,
                        'cvss_score': cvss_data.get('score'),
                        'severity': cvss_data.get('severity'),
                        'cvss_vector': cvss_data.get('vector'),
                        'affected_products': affected_products,
                        'cpe_entries': cpe_entries,
                        'raw_data': json.dumps(cve_item)  # Store for detailed analysis
                    }
                    
                    cves.append(cve_data)
                
                logger.info(f"Filtered to {len(cves)} recent CVEs (within {days_back} days)")
                return cves
                
        except Exception as e:
            logger.error(f"Error parsing CVE file {file_path}: {e}")
            return []
    
    def get_asset_keywords(self, db: Session) -> Set[str]:
        """Extract keywords from assets for CVE relevance filtering"""
        try:
            keywords = set()
            
            # Get assets with identifiable services
            assets = db.query(Asset).filter(
                or_(
                    Asset.primary_service.isnot(None),
                    Asset.service_vendor.isnot(None),
                    Asset.additional_services.isnot(None),
                    Asset.operating_system.isnot(None)
                )
            ).all()
            
            logger.info(f"Found {len(assets)} assets with service information")
            
            for asset in assets:
                # Primary service keywords
                if asset.primary_service:
                    keywords.update(self._extract_keywords(asset.primary_service))
                
                if asset.service_vendor:
                    keywords.update(self._extract_keywords(asset.service_vendor))
                
                # Operating system keywords
                if asset.operating_system:
                    keywords.update(self._extract_keywords(asset.operating_system))
                
                # Additional services
                if asset.additional_services:
                    for service in asset.additional_services:
                        if isinstance(service, dict):
                            if service.get('name'):
                                keywords.update(self._extract_keywords(service['name']))
                            if service.get('vendor'):
                                keywords.update(self._extract_keywords(service['vendor']))
            
            # Filter out common/generic words
            filtered_keywords = {kw for kw in keywords if len(kw) > 2 and kw.lower() not in 
                               {'service', 'server', 'system', 'application', 'software', 'version'}}
            
            logger.info(f"Extracted {len(filtered_keywords)} keywords from assets: {sorted(list(filtered_keywords))[:10]}...")
            return filtered_keywords
            
        except Exception as e:
            logger.error(f"Error extracting asset keywords: {e}")
            return set()
    
    def _extract_keywords(self, text: str) -> Set[str]:
        """Extract meaningful keywords from text"""
        if not text:
            return set()
        
        # Split on common delimiters and clean
        words = re.split(r'[\s\-_./]+', text.lower())
        return {word.strip() for word in words if word.strip() and len(word.strip()) > 2}
    
    def is_cve_relevant_to_assets(self, description: str, cpe_entries: List[str], asset_keywords: Set[str]) -> bool:
        """Check if a CVE is relevant to our assets"""
        if not asset_keywords:
            return True  # If no keywords, include all CVEs
        
        # Check description for asset keywords
        description_lower = description.lower()
        for keyword in asset_keywords:
            if keyword.lower() in description_lower:
                return True
        
        # Check CPE entries for asset keywords
        for cpe in cpe_entries:
            cpe_lower = cpe.lower()
            for keyword in asset_keywords:
                if keyword.lower() in cpe_lower:
                    return True
        
        return False
    
    async def collect_cves_from_files(self, db: Session, days_back: int = 7, years_back: int = 3) -> List[Dict]:
        """Collect CVEs from downloaded files, filtered by asset relevance"""
        try:
            # Get asset keywords for filtering
            asset_keywords = self.get_asset_keywords(db)
            
            # Download recent CVE files
            downloaded_files = await self.download_recent_cve_files(years_back)
            
            if not downloaded_files:
                logger.warning("No CVE files available for processing")
                return []
            
            all_relevant_cves = []
            
            for file_path in downloaded_files:
                try:
                    logger.info(f"Processing CVE file: {file_path}")
                    file_cves = self.parse_cve_file(file_path, days_back=days_back)
                    
                    # Filter CVEs based on asset relevance
                    for cve_data in file_cves:
                        description = cve_data.get("description", "")
                        cpe_entries = cve_data.get("cpe_entries", [])
                        
                        if self.is_cve_relevant_to_assets(description, cpe_entries, asset_keywords):
                            all_relevant_cves.append(cve_data)
                            logger.debug(f"CVE {cve_data['cve_id']} is relevant to our assets")
                    
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
    
    async def collect_recent_cves_api(self, db: Session, days_back: int = 7) -> List[Dict]:
        """Collect CVEs from NVD API, filtered by asset relevance"""
        try:
            asset_keywords = self.get_asset_keywords(db)
            
            if not asset_keywords:
                logger.info("No assets found with service information. Collecting generic CVEs.")
                return await self._collect_generic_recent_cves(days_back)
            
            # Build date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'resultsPerPage': 2000
            }
            
            all_cves = []
            start_index = 0
            
            async with httpx.AsyncClient(timeout=60.0) as client:
                while True:
                    params['startIndex'] = start_index
                    
                    try:
                        response = await client.get(
                            self.nvd_base_url,
                            params=params,
                            headers=self.headers
                        )
                        response.raise_for_status()
                        
                        data = response.json()
                        vulnerabilities = data.get('vulnerabilities', [])
                        
                        if not vulnerabilities:
                            break
                        
                        for vuln in vulnerabilities:
                            cve_item = vuln.get('cve', {})
                            cve_data = self._process_cve_item(cve_item)
                            
                            if cve_data and self.is_cve_relevant_to_assets(
                                cve_data.get('description', ''),
                                cve_data.get('cpe_entries', []),
                                asset_keywords
                            ):
                                all_cves.append(cve_data)
                        
                        # Check if we have more results
                        total_results = data.get('totalResults', 0)
                        if start_index + len(vulnerabilities) >= total_results:
                            break
                        
                        start_index += len(vulnerabilities)
                        
                        # Rate limiting
                        await asyncio.sleep(self.request_delay)
                        
                    except httpx.HTTPStatusError as e:
                        logger.error(f"HTTP error during API collection: {e}")
                        break
                    except Exception as e:
                        logger.error(f"Error during API collection: {e}")
                        break
            
            logger.info(f"Collected {len(all_cves)} relevant CVEs from API")
            return all_cves
            
        except Exception as e:
            logger.error(f"Error collecting CVEs from API: {e}")
            return []
    
    async def _collect_generic_recent_cves(self, days_back: int) -> List[Dict]:
        """Collect recent CVEs without asset filtering (fallback)"""
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'resultsPerPage': 100  # Limit for generic collection
            }
            
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    self.nvd_base_url,
                    params=params,
                    headers=self.headers
                )
                response.raise_for_status()
                
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                cves = []
                for vuln in vulnerabilities:
                    cve_item = vuln.get('cve', {})
                    cve_data = self._process_cve_item(cve_item)
                    if cve_data:
                        cves.append(cve_data)
                
                logger.info(f"Collected {len(cves)} generic recent CVEs")
                return cves
                
        except Exception as e:
            logger.error(f"Error collecting generic CVEs: {e}")
            return []
    
    def _process_cve_item(self, cve_item: Dict) -> Optional[Dict]:
        """Process a single CVE item into our format"""
        try:
            cve_id = cve_item.get('id', '')
            if not cve_id:
                return None
            
            # Extract description
            descriptions = cve_item.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Extract CVSS data
            cvss_data = self._extract_cvss_data(cve_item)
            
            # Extract CPE information  
            affected_products = self._extract_affected_products(cve_item)
            cpe_entries = self._extract_cpe_entries(cve_item)
            
            return {
                'cve_id': cve_id,
                'description': description,
                'published_date': cve_item.get('published', ''),
                'cvss_score': cvss_data.get('score'),
                'severity': cvss_data.get('severity'),
                'cvss_vector': cvss_data.get('vector'),
                'affected_products': affected_products,
                'cpe_entries': cpe_entries,
                'raw_data': json.dumps(cve_item)
            }
            
        except Exception as e:
            logger.error(f"Error processing CVE item: {e}")
            return None
    
    def _extract_cvss_data(self, cve_item: Dict) -> Dict:
        """Extract CVSS score and severity information"""
        cvss_data = {'score': None, 'severity': None, 'vector': None}
        
        try:
            metrics = cve_item.get('metrics', {})
            
            # Try CVSS v3.1 first
            cvss_v31 = metrics.get('cvssMetricV31', [])
            if cvss_v31:
                metric = cvss_v31[0]
                cvss_info = metric.get('cvssData', {})
                cvss_data['score'] = cvss_info.get('baseScore')
                cvss_data['severity'] = cvss_info.get('baseSeverity', '').upper()
                cvss_data['vector'] = cvss_info.get('vectorString')
                return cvss_data
            
            # Try CVSS v3.0
            cvss_v30 = metrics.get('cvssMetricV30', [])
            if cvss_v30:
                metric = cvss_v30[0]
                cvss_info = metric.get('cvssData', {})
                cvss_data['score'] = cvss_info.get('baseScore')
                cvss_data['severity'] = cvss_info.get('baseSeverity', '').upper()
                cvss_data['vector'] = cvss_info.get('vectorString')
                return cvss_data
            
            # Try CVSS v2.0
            cvss_v2 = metrics.get('cvssMetricV2', [])
            if cvss_v2:
                metric = cvss_v2[0]
                cvss_info = metric.get('cvssData', {})
                cvss_data['score'] = cvss_info.get('baseScore')
                cvss_data['vector'] = cvss_info.get('vectorString')
                # Map v2 score to severity
                score = cvss_info.get('baseScore', 0)
                if score >= 7.0:
                    cvss_data['severity'] = 'HIGH'
                elif score >= 4.0:
                    cvss_data['severity'] = 'MEDIUM'
                else:
                    cvss_data['severity'] = 'LOW'
        
        except Exception as e:
            logger.debug(f"Error extracting CVSS data: {e}")
        
        return cvss_data
    
    def _extract_affected_products(self, cve_item: Dict) -> Dict:
        """Extract affected products information"""
        try:
            configurations = cve_item.get('configurations', [])
            products = {}
            
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    for match in cpe_matches:
                        cpe_name = match.get('criteria', '')
                        if cpe_name and cpe_name.startswith('cpe:'):
                            # Parse CPE name (cpe:2.3:a:vendor:product:version:...)
                            parts = cpe_name.split(':')
                            if len(parts) >= 5:
                                vendor = parts[3] if parts[3] != '*' else ''
                                product = parts[4] if parts[4] != '*' else ''
                                version = parts[5] if len(parts) > 5 and parts[5] != '*' else ''
                                
                                if vendor or product:
                                    key = f"{vendor}:{product}".strip(':')
                                    if key not in products:
                                        products[key] = []
                                    if version and version not in products[key]:
                                        products[key].append(version)
            
            return products
            
        except Exception as e:
            logger.debug(f"Error extracting affected products: {e}")
            return {}
    
    def _extract_cpe_entries(self, cve_item: Dict) -> List[str]:
        """Extract CPE entries from CVE"""
        try:
            cpe_entries = []
            configurations = cve_item.get('configurations', [])
            
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    for match in cpe_matches:
                        cpe_name = match.get('criteria', '')
                        if cpe_name and cpe_name not in cpe_entries:
                            cpe_entries.append(cpe_name)
            
            return cpe_entries
            
        except Exception as e:
            logger.debug(f"Error extracting CPE entries: {e}")
            return []
    
    async def store_cves(self, db: Session, cves_data: List[Dict]) -> Dict[str, int]:
        """Store CVE data in database"""
        stats = {'stored': 0, 'updated': 0, 'skipped': 0, 'errors': 0}
        
        try:
            for cve_data in cves_data:
                try:
                    cve_id = cve_data.get('cve_id')
                    if not cve_id:
                        stats['skipped'] += 1
                        continue
                    
                    # Check if CVE already exists
                    existing_cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
                    
                    if existing_cve:
                        # Update existing CVE
                        existing_cve.description = cve_data.get('description', existing_cve.description)
                        existing_cve.cvss_score = cve_data.get('cvss_score', existing_cve.cvss_score)
                        existing_cve.severity = cve_data.get('severity', existing_cve.severity)
                        existing_cve.cvss_vector = cve_data.get('cvss_vector', existing_cve.cvss_vector)
                        existing_cve.affected_products = cve_data.get('affected_products', existing_cve.affected_products)
                        existing_cve.cpe_entries = cve_data.get('cpe_entries', existing_cve.cpe_entries)
                        existing_cve.updated_at = datetime.now()
                        stats['updated'] += 1
                    else:
                        # Create new CVE
                        published_date = None
                        if cve_data.get('published_date'):
                            try:
                                published_date = datetime.fromisoformat(
                                    cve_data['published_date'].replace('Z', '+00:00')
                                ).replace(tzinfo=None)
                            except:
                                pass
                        
                        new_cve = CVE(
                            cve_id=cve_id,
                            description=cve_data.get('description', ''),
                            published_date=published_date,
                            cvss_score=cve_data.get('cvss_score'),
                            severity=cve_data.get('severity'),
                            cvss_vector=cve_data.get('cvss_vector'),
                            affected_products=cve_data.get('affected_products'),
                            cpe_entries=cve_data.get('cpe_entries'),
                            correlation_confidence=0.0,  # Will be updated by correlation engine
                            processed=False,  # Mark for processing
                            created_at=datetime.now(),
                            updated_at=datetime.now()
                        )
                        db.add(new_cve)
                        stats['stored'] += 1
                        
                except Exception as e:
                    logger.error(f"Error storing CVE {cve_data.get('cve_id', 'unknown')}: {e}")
                    stats['errors'] += 1
            
            db.commit()
            logger.info(f"CVE storage complete: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Error during CVE storage: {e}")
            db.rollback()
            stats['errors'] += len(cves_data)
            return stats
    
    async def run_asset_focused_collection(self, db: Session, days_back: int = 7, use_files: bool = True) -> Dict[str, int]:
        """
        Main collection method - Asset-focused CVE collection
        
        Args:
            db: Database session
            days_back: Number of days back to collect
            use_files: Whether to use file download (True) or API (False)
        
        Returns:
            Collection statistics
        """
        logger.info(f"Starting asset-focused CVE collection (days_back={days_back}, use_files={use_files})")
        
        try:
            # Collect CVEs based on method preference
            if use_files:
                logger.info("Using file-based collection method")
                cves_data = await self.collect_cves_from_files(db, days_back)
            else:
                logger.info("Using API-based collection method")
                cves_data = await self.collect_recent_cves_api(db, days_back)
            
            if not cves_data:
                logger.warning("No CVE data collected")
                return {'collected': 0, 'stored': 0, 'updated': 0, 'skipped': 0, 'errors': 0}
            
            # Store collected CVEs
            storage_stats = await self.store_cves(db, cves_data)
            
            # Combine statistics
            final_stats = {
                'collected': len(cves_data),
                **storage_stats
            }
            
            logger.info(f"Asset-focused CVE collection completed: {final_stats}")
            return final_stats
            
        except Exception as e:
            logger.error(f"Asset-focused CVE collection failed: {e}")
            return {'collected': 0, 'stored': 0, 'updated': 0, 'skipped': 0, 'errors': 1}
    
    # Backward compatibility methods (keeping existing interface)
    async def collect_recent_cves(self, db: Session, days_back: int = 7) -> List[Dict]:
        """Legacy method - redirects to asset-focused collection"""
        logger.info("Legacy collect_recent_cves called - redirecting to asset-focused collection")
        return await self.collect_recent_cves_api(db, days_back)
    
    async def run_service_specific_collection(self, db: Session, days_back: int = 7, use_files: bool = True):
        """Legacy method - redirects to asset-focused collection"""
        logger.info("Legacy run_service_specific_collection called - redirecting to asset-focused collection")
        return await self.run_asset_focused_collection(db, days_back, use_files)
    
    def get_service_keywords(self, db: Session) -> Set[str]:
        """Legacy method - redirects to asset keywords"""
        logger.info("Legacy get_service_keywords called - redirecting to asset keywords")
        return self.get_asset_keywords(db)
    
    def is_cve_relevant(self, description: str, keywords: Set[str]) -> bool:
        """Legacy method - redirects to asset relevance check"""
        return self.is_cve_relevant_to_assets(description, [], keywords)