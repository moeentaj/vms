"""
Enhanced CPE Dictionary and Matching Manager
app/services/enhanced_cpe_dictionary.py

Integrates NIST CPE Dictionary 2.0 and CPE Match 2.0 feeds for comprehensive CPE support.
Builds upon your existing enhanced_cpe_engine.py with full NIST data feed integration.
"""

import asyncio
import json
import logging
import time
import gzip
import tarfile
import re
import httpx
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from urllib.parse import unquote
import tempfile
import os
import hashlib
from collections import defaultdict

from app.core.config import settings
from app.core.database import get_db

logger = logging.getLogger(__name__)

@dataclass
class CPEDictionaryProduct:
    """Enhanced CPE product from NIST CPE Dictionary 2.0"""
    cpe_name: str  # CPE 2.3 formatted string
    cpe_name_id: str  # NIST UUID
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str
    
    # Enhanced metadata
    titles: List[Dict[str, str]]  # Multi-language titles
    references: List[Dict[str, str]]  # External references
    deprecated: bool = False
    deprecation_date: Optional[datetime] = None
    deprecated_by: List[str] = None  # Replacement CPEs
    
    # Derived metadata
    categories: List[str] = None
    keywords: List[str] = None
    alternative_names: List[str] = None
    vendor_aliases: List[str] = None
    popularity_score: float = 0.0
    
    # Timestamps
    last_modified: Optional[datetime] = None
    created: Optional[datetime] = None

@dataclass
class CPEMatch:
    """CPE Match entry from NIST CPE Match 2.0"""
    cpe_name: str
    match_criteria_id: str
    vulnerable: bool = False
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    match_string: Optional[str] = None
    
    # Version range metadata
    has_version_range: bool = False
    affects_all_versions: bool = False

class EnhancedCPEDictionaryManager:
    """
    Enhanced CPE Dictionary Manager with NIST CPE 2.0 and CPE Match 2.0 integration
    Builds upon your existing enhanced_cpe_engine architecture
    """
    
    def __init__(self, db: Session):
        self.db = db
        
        # NIST CPE 2.0 Data Feed URLs
        self.cpe_dictionary_url = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"
        self.cpe_match_url = "https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.tar.gz"
        
        # Cache configuration
        self.cache_dir = Path(getattr(settings, 'CPE_CACHE_DIR', './cache/cpe'))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir = self.cache_dir / "temp"
        self.temp_dir.mkdir(exist_ok=True)
        
        # Cache files
        self.dictionary_cache_file = self.cache_dir / "cpe_dictionary_2.0.json"
        self.match_cache_file = self.cache_dir / "cpe_match_2.0.json"
        self.enhanced_cache_file = self.cache_dir / "enhanced_cpe_products.json"
        
        # In-memory storage
        self.cpe_products: List[CPEDictionaryProduct] = []
        self.cpe_matches: List[CPEMatch] = []
        
        # Search optimization indices
        self._vendor_index: Dict[str, List[int]] = {}
        self._product_index: Dict[str, List[int]] = {}
        self._category_index: Dict[str, List[int]] = {}
        self._keyword_index: Dict[str, List[int]] = {}
        self._cpe_name_index: Dict[str, int] = {}
        
        # Category patterns for auto-classification
        self.category_patterns = self._build_category_patterns()
        self.category_weights = self._build_category_weights()

    async def download_nist_data_feed(self, url: str, filename: str, force_download: bool = False) -> Optional[Path]:
        """Download NIST data feed (CPE Dictionary or CPE Match)"""
        try:
            local_file = self.temp_dir / filename
            
            # Check if file exists and is fresh (less than 24 hours old)
            if not force_download and local_file.exists():
                file_age = datetime.now() - datetime.fromtimestamp(local_file.stat().st_mtime)
                if file_age < timedelta(hours=24):
                    logger.info(f"Using cached {filename} (age: {file_age})")
                    return local_file
            
            logger.info(f"Downloading {filename} from {url}")
            
            async with httpx.AsyncClient(timeout=600.0) as client:
                response = await client.get(url)
                response.raise_for_status()
                
                with open(local_file, 'wb') as f:
                    f.write(response.content)
                
                logger.info(f"Downloaded {filename} ({len(response.content)} bytes)")
                return local_file
                
        except Exception as e:
            logger.error(f"Failed to download {filename}: {e}")
            return None

    def extract_and_process_cpe_dictionary(self, archive_path: Path) -> List[CPEDictionaryProduct]:
        """Extract and process CPE Dictionary 2.0 archive"""
        products = []
        
        try:
            logger.info("Processing CPE Dictionary 2.0 archive")
            
            with tarfile.open(archive_path, 'r:gz') as tar:
                for member in tar.getmembers():
                    if member.isfile() and member.name.endswith('.json'):
                        logger.info(f"Processing CPE Dictionary file: {member.name}")
                        
                        json_file = tar.extractfile(member)
                        if json_file:
                            try:
                                json_data = json.load(json_file)
                                
                                # Process CPE Dictionary 2.0 format
                                cpe_items = json_data.get('products', [])
                                for item in cpe_items:
                                    product = self._parse_cpe_dictionary_product(item)
                                    if product and self._is_relevant_product(product):
                                        products.append(product)
                                
                                logger.info(f"Processed {len(cpe_items)} CPE dictionary entries from {member.name}")
                                
                            except json.JSONDecodeError as e:
                                logger.error(f"Failed to parse JSON from {member.name}: {e}")
            
            logger.info(f"Total CPE Dictionary products processed: {len(products)}")
            return products
            
        except Exception as e:
            logger.error(f"Failed to process CPE Dictionary archive: {e}")
            return []

    def extract_and_process_cpe_match(self, archive_path: Path) -> List[CPEMatch]:
        """Extract and process CPE Match 2.0 archive"""
        matches = []
        
        try:
            logger.info("Processing CPE Match 2.0 archive")
            
            with tarfile.open(archive_path, 'r:gz') as tar:
                for member in tar.getmembers():
                    if member.isfile() and member.name.endswith('.json'):
                        logger.info(f"Processing CPE Match file: {member.name}")
                        
                        json_file = tar.extractfile(member)
                        if json_file:
                            try:
                                json_data = json.load(json_file)
                                
                                # Process CPE Match 2.0 format
                                match_strings = json_data.get('matches', [])
                                for match_data in match_strings:
                                    match = self._parse_cpe_match(match_data)
                                    if match:
                                        matches.append(match)
                                
                                logger.info(f"Processed {len(match_strings)} CPE match entries from {member.name}")
                                
                            except json.JSONDecodeError as e:
                                logger.error(f"Failed to parse JSON from {member.name}: {e}")
            
            logger.info(f"Total CPE Match entries processed: {len(matches)}")
            return matches
            
        except Exception as e:
            logger.error(f"Failed to process CPE Match archive: {e}")
            return []

    def _parse_cpe_dictionary_product(self, cpe_item: Dict) -> Optional[CPEDictionaryProduct]:
        """Parse a single CPE Dictionary 2.0 product entry"""
        try:
            cpe_data = cpe_item.get('cpe', {})
            
            # Extract CPE components
            cpe_name = cpe_data.get('cpeName', '')
            cpe_name_id = cpe_data.get('cpeNameId', '')
            
            if not cpe_name or not cpe_name_id:
                return None
            
            # Parse CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
            cpe_parts = cpe_name.split(':')
            if len(cpe_parts) < 13:
                logger.warning(f"Invalid CPE format: {cpe_name}")
                return None
            
            # Extract and normalize CPE components
            vendor = self._normalize_cpe_component(cpe_parts[3])
            product = self._normalize_cpe_component(cpe_parts[4])
            version = self._normalize_cpe_component(cpe_parts[5])
            update = self._normalize_cpe_component(cpe_parts[6])
            edition = self._normalize_cpe_component(cpe_parts[7])
            language = self._normalize_cpe_component(cpe_parts[8])
            sw_edition = self._normalize_cpe_component(cpe_parts[9])
            target_sw = self._normalize_cpe_component(cpe_parts[10])
            target_hw = self._normalize_cpe_component(cpe_parts[11])
            other = self._normalize_cpe_component(cpe_parts[12])
            
            # Extract titles and references
            titles = cpe_data.get('titles', [])
            references = cpe_data.get('refs', [])
            
            # Parse timestamps
            last_modified = self._parse_timestamp(cpe_data.get('lastModifiedDate'))
            created = self._parse_timestamp(cpe_data.get('created'))
            
            # Handle deprecation
            deprecated = cpe_data.get('deprecated', False)
            deprecation_date = None
            deprecated_by = []
            
            if deprecated and 'deprecation' in cpe_data:
                deprecation_info = cpe_data['deprecation']
                deprecation_date = self._parse_timestamp(deprecation_info.get('date'))
                deprecated_by = deprecation_info.get('deprecatedBy', [])
            
            product_obj = CPEDictionaryProduct(
                cpe_name=cpe_name,
                cpe_name_id=cpe_name_id,
                vendor=vendor,
                product=product,
                version=version,
                update=update,
                edition=edition,
                language=language,
                sw_edition=sw_edition,
                target_sw=target_sw,
                target_hw=target_hw,
                other=other,
                titles=titles,
                references=references,
                deprecated=deprecated,
                deprecation_date=deprecation_date,
                deprecated_by=deprecated_by,
                last_modified=last_modified,
                created=created
            )
            
            # Enhance with metadata
            self._enhance_product_metadata(product_obj)
            
            return product_obj
            
        except Exception as e:
            logger.error(f"Failed to parse CPE dictionary product: {e}")
            return None

    def _parse_cpe_match(self, match_data: Dict) -> Optional[CPEMatch]:
        """Parse a single CPE Match 2.0 entry"""
        try:
            cpe_name = match_data.get('cpeName', '')
            match_criteria_id = match_data.get('matchCriteriaId', '')
            
            if not cpe_name or not match_criteria_id:
                return None
            
            # Extract version range information
            vulnerable = match_data.get('vulnerable', False)
            version_start_including = match_data.get('versionStartIncluding')
            version_start_excluding = match_data.get('versionStartExcluding')
            version_end_including = match_data.get('versionEndIncluding')
            version_end_excluding = match_data.get('versionEndExcluding')
            match_string = match_data.get('matchString')
            
            # Determine if this has version range criteria
            has_version_range = any([
                version_start_including,
                version_start_excluding,
                version_end_including,
                version_end_excluding
            ])
            
            # Check if it affects all versions
            affects_all_versions = (
                not has_version_range and
                '*' in cpe_name.split(':')[5]  # version component is wildcard
            )
            
            return CPEMatch(
                cpe_name=cpe_name,
                match_criteria_id=match_criteria_id,
                vulnerable=vulnerable,
                version_start_including=version_start_including,
                version_start_excluding=version_start_excluding,
                version_end_including=version_end_including,
                version_end_excluding=version_end_excluding,
                match_string=match_string,
                has_version_range=has_version_range,
                affects_all_versions=affects_all_versions
            )
            
        except Exception as e:
            logger.error(f"Failed to parse CPE match: {e}")
            return None

    def _enhance_product_metadata(self, product: CPEDictionaryProduct):
        """Enhance product with categories, keywords, and other metadata"""
        try:
            # Initialize lists if None
            if product.categories is None:
                product.categories = []
            if product.keywords is None:
                product.keywords = []
            if product.alternative_names is None:
                product.alternative_names = []
            if product.vendor_aliases is None:
                product.vendor_aliases = []
            
            # Extract categories based on patterns
            categories = self._extract_categories(product)
            product.categories.extend(categories)
            
            # Generate keywords
            keywords = self._extract_keywords(product)
            product.keywords.extend(keywords)
            
            # Generate alternative names from titles
            for title_entry in product.titles:
                title_text = title_entry.get('title', '').lower()
                if title_text and title_text not in product.alternative_names:
                    product.alternative_names.append(title_text)
            
            # Calculate popularity score
            product.popularity_score = self._calculate_popularity_score(product)
            
        except Exception as e:
            logger.error(f"Failed to enhance product metadata: {e}")

    def _extract_categories(self, product: CPEDictionaryProduct) -> List[str]:
        """Extract categories based on product information"""
        categories = []
        
        search_text = f"{product.vendor} {product.product}".lower()
        
        for category, patterns in self.category_patterns.items():
            for pattern in patterns:
                if re.search(pattern, search_text):
                    categories.append(category)
                    break
        
        return categories

    def _extract_keywords(self, product: CPEDictionaryProduct) -> List[str]:
        """Extract search keywords from product information"""
        keywords = set()
        
        # Add vendor and product as keywords
        if product.vendor and product.vendor != '*':
            keywords.add(product.vendor.lower())
        if product.product and product.product != '*':
            keywords.add(product.product.lower())
        
        # Extract from titles
        for title_entry in product.titles:
            title_text = title_entry.get('title', '')
            if title_text:
                # Split and clean words
                words = re.findall(r'\w+', title_text.lower())
                keywords.update(word for word in words if len(word) > 2)
        
        return list(keywords)

    def _calculate_popularity_score(self, product: CPEDictionaryProduct) -> float:
        """Calculate popularity score based on various factors"""
        score = 0.0
        
        # Base score for having references
        score += len(product.references) * 0.1
        
        # Category-based scoring
        for category in product.categories:
            weight = self.category_weights.get(category, 0.5)
            score += weight
        
        # Recency bonus
        if product.last_modified:
            days_old = (datetime.now() - product.last_modified).days
            if days_old < 365:  # Less than a year old
                score += max(0.5, 1.0 - (days_old / 365))
        
        # Version specificity (more specific versions are often more popular)
        if product.version and product.version != '*':
            score += 0.2
        
        return min(10.0, score)  # Cap at 10.0

    def _normalize_cpe_component(self, component: str) -> str:
        """Normalize CPE component (handle URL encoding and formatting)"""
        if not component or component == '*':
            return component
        
        try:
            # URL decode
            decoded = unquote(component)
            # Replace common separators with spaces for readability
            normalized = decoded.replace('_', ' ').replace('-', ' ')
            return normalized.strip()
        except:
            return component

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO timestamp from NIST data"""
        if not timestamp_str:
            return None
        
        try:
            # Handle various timestamp formats
            cleaned = timestamp_str.replace('Z', '+00:00')
            return datetime.fromisoformat(cleaned)
        except:
            try:
                # Fallback for different formats
                return datetime.strptime(timestamp_str.split('T')[0], '%Y-%m-%d')
            except:
                return None

    def _is_relevant_product(self, product: CPEDictionaryProduct) -> bool:
        """Filter for relevant products"""
        # Skip if no meaningful vendor/product info
        if not product.vendor or not product.product:
            return False
        
        if product.vendor == '*' or product.product == '*':
            return False
        
        # Skip deprecated unless configured to include
        if product.deprecated and not getattr(settings, 'CPE_INCLUDE_DEPRECATED', False):
            return False
        
        # Include based on CPE type
        if product.cpe_name.startswith('cpe:2.3:a:'):  # Applications
            return True
        if product.cpe_name.startswith('cpe:2.3:o:'):  # Operating Systems
            return True
        if product.cpe_name.startswith('cpe:2.3:h:'):  # Hardware
            # Include only if it has relevant categories
            return len(product.categories or []) > 0
        
        return False

    def _build_category_patterns(self) -> Dict[str, List[str]]:
        """Build category matching patterns"""
        return {
            'web_server': [
                r'apache.*http', r'nginx', r'iis', r'tomcat', r'jetty',
                r'lighttpd', r'caddy', r'traefik', r'haproxy'
            ],
            'database': [
                r'mysql', r'postgresql', r'oracle.*database', r'mongodb',
                r'redis', r'cassandra', r'elasticsearch', r'mariadb',
                r'sqlite', r'mssql', r'sql.*server'
            ],
            'operating_system': [
                r'windows.*server', r'ubuntu', r'centos', r'rhel', r'debian',
                r'linux', r'macos', r'android', r'ios', r'freebsd'
            ],
            'application_server': [
                r'tomcat', r'jboss', r'websphere', r'weblogic', r'glassfish'
            ],
            'browser': [
                r'chrome', r'firefox', r'safari', r'edge', r'internet.*explorer'
            ],
            'development_tools': [
                r'git', r'jenkins', r'maven', r'gradle', r'npm', r'yarn',
                r'docker', r'kubernetes', r'ansible'
            ],
            'security_tools': [
                r'openssl', r'wireshark', r'nmap', r'metasploit', r'nessus'
            ],
            'cms': [
                r'wordpress', r'drupal', r'joomla', r'magento'
            ],
            'programming_language': [
                r'python', r'java', r'nodejs', r'php', r'ruby', r'go'
            ]
        }

    def _build_category_weights(self) -> Dict[str, float]:
        """Build category importance weights"""
        return {
            'web_server': 1.0,
            'database': 1.0,
            'operating_system': 1.0,
            'application_server': 0.9,
            'cms': 0.8,
            'security_tools': 0.8,
            'browser': 0.7,
            'development_tools': 0.6,
            'programming_language': 0.5
        }

    async def ingest_complete_cpe_data(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Complete CPE data ingestion from NIST feeds"""
        stats = {
            'started_at': datetime.now().isoformat(),
            'cpe_dictionary_products': 0,
            'cpe_matches': 0,
            'total_processing_time': 0,
            'errors': [],
            'warnings': [],
            'cache_files_created': []
        }
        
        start_time = time.time()
        
        try:
            logger.info("Starting complete CPE data ingestion")
            
            # Download CPE Dictionary 2.0
            dict_file = await self.download_nist_data_feed(
                self.cpe_dictionary_url, 
                "nvdcpe-2.0.tar.gz", 
                force_refresh
            )
            
            if dict_file:
                # Process CPE Dictionary
                self.cpe_products = self.extract_and_process_cpe_dictionary(dict_file)
                stats['cpe_dictionary_products'] = len(self.cpe_products)
                
                # Save dictionary cache
                await self._save_dictionary_cache()
                stats['cache_files_created'].append(str(self.dictionary_cache_file))
            else:
                stats['errors'].append("Failed to download CPE Dictionary")
            
            # Download CPE Match 2.0
            match_file = await self.download_nist_data_feed(
                self.cpe_match_url, 
                "nvdcpematch-2.0.tar.gz", 
                force_refresh
            )
            
            if match_file:
                # Process CPE Match
                self.cpe_matches = self.extract_and_process_cpe_match(match_file)
                stats['cpe_matches'] = len(self.cpe_matches)
                
                # Save match cache
                await self._save_match_cache()
                stats['cache_files_created'].append(str(self.match_cache_file))
            else:
                stats['errors'].append("Failed to download CPE Match data")
            
            # Build search indices
            if self.cpe_products:
                self._build_search_indices()
                
                # Create enhanced cache
                await self._save_enhanced_cache()
                stats['cache_files_created'].append(str(self.enhanced_cache_file))
            
            stats['total_processing_time'] = time.time() - start_time
            stats['completed_at'] = datetime.now().isoformat()
            
            logger.info(f"CPE ingestion completed in {stats['total_processing_time']:.2f}s")
            logger.info(f"Products: {stats['cpe_dictionary_products']}, Matches: {stats['cpe_matches']}")
            
            return stats
            
        except Exception as e:
            stats['errors'].append(f"Ingestion failed: {str(e)}")
            logger.error(f"CPE ingestion failed: {e}")
            return stats

    async def _save_dictionary_cache(self):
        """Save CPE dictionary products to cache"""
        try:
            cache_data = {
                'products': [asdict(product) for product in self.cpe_products],
                'cached_at': datetime.now().isoformat(),
                'total_count': len(self.cpe_products)
            }
            
            with open(self.dictionary_cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, default=str, ensure_ascii=False, indent=2)
            
            logger.info(f"Saved {len(self.cpe_products)} products to dictionary cache")
            
        except Exception as e:
            logger.error(f"Failed to save dictionary cache: {e}")

    async def _save_match_cache(self):
        """Save CPE match data to cache"""
        try:
            cache_data = {
                'matches': [asdict(match) for match in self.cpe_matches],
                'cached_at': datetime.now().isoformat(),
                'total_count': len(self.cpe_matches)
            }
            
            with open(self.match_cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, default=str, ensure_ascii=False, indent=2)
            
            logger.info(f"Saved {len(self.cpe_matches)} matches to cache")
            
        except Exception as e:
            logger.error(f"Failed to save match cache: {e}")

    async def _save_enhanced_cache(self):
        """Save enhanced searchable cache"""
        try:
            # Create enhanced search data
            enhanced_products = []
            for product in self.cpe_products:
                enhanced_product = asdict(product)
                enhanced_products.append(enhanced_product)
            
            cache_data = {
                'products': enhanced_products,
                'search_indices': {
                    'vendor_index': {k: list(v) for k, v in self._vendor_index.items()},
                    'product_index': {k: list(v) for k, v in self._product_index.items()},
                    'category_index': {k: list(v) for k, v in self._category_index.items()},
                    'keyword_index': {k: list(v) for k, v in self._keyword_index.items()},
                    'cpe_name_index': self._cpe_name_index
                },
                'cached_at': datetime.now().isoformat(),
                'total_count': len(enhanced_products),
                'version': '2.0'
            }
            
            with open(self.enhanced_cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, default=str, ensure_ascii=False, indent=2)
            
            logger.info(f"Saved enhanced cache with {len(enhanced_products)} products")
            
        except Exception as e:
            logger.error(f"Failed to save enhanced cache: {e}")

    def load_cached_data(self) -> bool:
        """Load cached CPE data"""
        try:
            # Load enhanced cache if available
            if self.enhanced_cache_file.exists():
                with open(self.enhanced_cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                
                # Load products
                product_data = cache_data.get('products', [])
                self.cpe_products = []
                
                for product_dict in product_data:
                    # Convert back to dataclass
                    # Handle datetime fields
                    for date_field in ['last_modified', 'created', 'deprecation_date']:
                        if product_dict.get(date_field):
                            try:
                                product_dict[date_field] = datetime.fromisoformat(product_dict[date_field])
                            except:
                                product_dict[date_field] = None
                    
                    product = CPEDictionaryProduct(**product_dict)
                    self.cpe_products.append(product)
                
                # Load search indices
                indices = cache_data.get('search_indices', {})
                self._vendor_index = {k: list(v) for k, v in indices.get('vendor_index', {}).items()}
                self._product_index = {k: list(v) for k, v in indices.get('product_index', {}).items()}
                self._category_index = {k: list(v) for k, v in indices.get('category_index', {}).items()}
                self._keyword_index = {k: list(v) for k, v in indices.get('keyword_index', {}).items()}
                self._cpe_name_index = indices.get('cpe_name_index', {})
                
                logger.info(f"Loaded {len(self.cpe_products)} products from enhanced cache")
                return True
                
            # Fallback to dictionary cache
            elif self.dictionary_cache_file.exists():
                with open(self.dictionary_cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                
                product_data = cache_data.get('products', [])
                self.cpe_products = []
                
                for product_dict in product_data:
                    # Handle datetime fields
                    for date_field in ['last_modified', 'created', 'deprecation_date']:
                        if product_dict.get(date_field):
                            try:
                                product_dict[date_field] = datetime.fromisoformat(product_dict[date_field])
                            except:
                                product_dict[date_field] = None
                    
                    product = CPEDictionaryProduct(**product_dict)
                    self.cpe_products.append(product)
                
                # Rebuild indices
                self._build_search_indices()
                
                logger.info(f"Loaded {len(self.cpe_products)} products from dictionary cache")
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Failed to load cached data: {e}")
            return False

    def _build_search_indices(self):
        """Build search indices for fast lookups"""
        logger.info("Building search indices...")
        
        self._vendor_index = defaultdict(list)
        self._product_index = defaultdict(list)
        self._category_index = defaultdict(list)
        self._keyword_index = defaultdict(list)
        self._cpe_name_index = {}
        
        for idx, product in enumerate(self.cpe_products):
            # Vendor index
            if product.vendor:
                vendor_key = product.vendor.lower().strip()
                self._vendor_index[vendor_key].append(idx)
            
            # Product index
            if product.product:
                product_key = product.product.lower().strip()
                self._product_index[product_key].append(idx)
            
            # Category index
            for category in (product.categories or []):
                category_key = category.lower().strip()
                self._category_index[category_key].append(idx)
            
            # Keyword index
            for keyword in (product.keywords or []):
                keyword_key = keyword.lower().strip()
                self._keyword_index[keyword_key].append(idx)
            
            # CPE name index
            self._cpe_name_index[product.cpe_name] = idx
            self._cpe_name_index[product.cpe_name_id] = idx
        
        logger.info(f"Built search indices: {len(self._vendor_index)} vendors, {len(self._product_index)} products")

    def enhanced_search(self, query: str, filters: Dict[str, Any] = None, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        """Enhanced search with multiple matching strategies"""
        start_time = time.time()
        filters = filters or {}
        
        try:
            if not self.cpe_products:
                return {
                    'products': [],
                    'total_count': 0,
                    'search_query': query,
                    'execution_time_ms': 0,
                    'message': 'No CPE data loaded'
                }
            
            # Normalize query
            normalized_query = query.lower().strip()
            query_terms = re.findall(r'\w+', normalized_query)
            
            # Multiple search strategies
            candidate_indices = set()
            
            # Strategy 1: Exact vendor/product matches
            for term in query_terms:
                if term in self._vendor_index:
                    candidate_indices.update(self._vendor_index[term])
                if term in self._product_index:
                    candidate_indices.update(self._product_index[term])
            
            # Strategy 2: Keyword matches
            for term in query_terms:
                if term in self._keyword_index:
                    candidate_indices.update(self._keyword_index[term])
            
            # Strategy 3: Fuzzy matching on vendor/product
            if not candidate_indices:
                candidate_indices = self._fuzzy_search(query_terms)
            
            # Strategy 4: Substring search as fallback
            if not candidate_indices:
                candidate_indices = self._substring_search(normalized_query)
            
            # Score and rank candidates
            scored_results = []
            for idx in candidate_indices:
                if idx < len(self.cpe_products):
                    product = self.cpe_products[idx]
                    score = self._calculate_search_score(product, query_terms, normalized_query)
                    
                    # Apply filters
                    if self._passes_filters(product, filters):
                        scored_results.append((score, idx, product))
            
            # Sort by score (descending)
            scored_results.sort(key=lambda x: x[0], reverse=True)
            
            # Apply pagination
            total_count = len(scored_results)
            paginated_results = scored_results[offset:offset + limit]
            
            # Format results
            products = []
            for score, idx, product in paginated_results:
                product_dict = asdict(product)
                product_dict['search_score'] = score
                # Convert datetime objects to strings
                for field in ['last_modified', 'created', 'deprecation_date']:
                    if product_dict.get(field):
                        product_dict[field] = product_dict[field].isoformat()
                products.append(product_dict)
            
            execution_time = int((time.time() - start_time) * 1000)
            
            return {
                'products': products,
                'total_count': total_count,
                'search_query': query,
                'normalized_query': normalized_query,
                'execution_time_ms': execution_time,
                'filters_applied': filters,
                'categories_found': self._extract_result_categories(products),
                'search_suggestions': self._generate_search_suggestions(query, products)
            }
            
        except Exception as e:
            logger.error(f"Enhanced search failed: {e}")
            return {
                'products': [],
                'total_count': 0,
                'search_query': query,
                'execution_time_ms': 0,
                'error': str(e)
            }

    def _fuzzy_search(self, query_terms: List[str]) -> Set[int]:
        """Fuzzy search using string similarity"""
        candidate_indices = set()
        
        # Search vendors
        for vendor, indices in self._vendor_index.items():
            for term in query_terms:
                if len(term) >= 3:  # Only fuzzy match longer terms
                    similarity = self._string_similarity(term, vendor)
                    if similarity > 0.6:  # 60% similarity threshold
                        candidate_indices.update(indices)
        
        # Search products
        for product, indices in self._product_index.items():
            for term in query_terms:
                if len(term) >= 3:
                    similarity = self._string_similarity(term, product)
                    if similarity > 0.6:
                        candidate_indices.update(indices)
        
        return candidate_indices

    def _substring_search(self, query: str) -> Set[int]:
        """Substring search as final fallback"""
        candidate_indices = set()
        
        for idx, product in enumerate(self.cpe_products):
            search_text = f"{product.vendor} {product.product}".lower()
            if query in search_text:
                candidate_indices.add(idx)
        
        return candidate_indices

    def _string_similarity(self, s1: str, s2: str) -> float:
        """Calculate string similarity using Levenshtein distance"""
        if not s1 or not s2:
            return 0.0
        
        if s1 == s2:
            return 1.0
        
        # Simple similarity based on common characters
        s1_set = set(s1.lower())
        s2_set = set(s2.lower())
        
        intersection = s1_set & s2_set
        union = s1_set | s2_set
        
        if not union:
            return 0.0
        
        return len(intersection) / len(union)

    def _calculate_search_score(self, product: CPEDictionaryProduct, query_terms: List[str], normalized_query: str) -> float:
        """Calculate relevance score for search results"""
        score = 0.0
        
        vendor_text = (product.vendor or '').lower()
        product_text = (product.product or '').lower()
        combined_text = f"{vendor_text} {product_text}"
        
        # Exact matches
        for term in query_terms:
            if term == vendor_text:
                score += 5.0
            elif term == product_text:
                score += 5.0
            elif term in vendor_text:
                score += 3.0
            elif term in product_text:
                score += 3.0
            elif term in combined_text:
                score += 1.0
        
        # Keyword matches
        for keyword in (product.keywords or []):
            if keyword.lower() in query_terms:
                score += 2.0
        
        # Category relevance
        for category in (product.categories or []):
            category_weight = self.category_weights.get(category, 0.5)
            score += category_weight
        
        # Popularity boost
        score += product.popularity_score * 0.1
        
        # Version specificity (prefer specific versions)
        if product.version and product.version != '*':
            score += 0.5
        
        # Deprecation penalty
        if product.deprecated:
            score *= 0.7
        
        return score

    def _passes_filters(self, product: CPEDictionaryProduct, filters: Dict[str, Any]) -> bool:
        """Check if product passes all filters"""
        if filters.get('vendor_filter'):
            if filters['vendor_filter'].lower() not in (product.vendor or '').lower():
                return False
        
        if filters.get('product_filter'):
            if filters['product_filter'].lower() not in (product.product or '').lower():
                return False
        
        if filters.get('version_filter'):
            if filters['version_filter'].lower() not in (product.version or '').lower():
                return False
        
        if filters.get('category_filter'):
            if filters['category_filter'].lower() not in [c.lower() for c in (product.categories or [])]:
                return False
        
        if not filters.get('include_deprecated', False) and product.deprecated:
            return False
        
        return True

    def _extract_result_categories(self, products: List[Dict]) -> List[str]:
        """Extract unique categories from search results"""
        categories = set()
        for product in products:
            product_categories = product.get('categories') or []
            categories.update(product_categories)
        return sorted(list(categories))

    def _generate_search_suggestions(self, query: str, results: List[Dict]) -> List[str]:
        """Generate search suggestions based on results and common patterns"""
        suggestions = []
        
        if len(results) == 0:
            # Suggest broader terms
            query_terms = query.lower().split()
            for term in query_terms:
                # Find similar vendors/products
                for vendor in self._vendor_index.keys():
                    if term in vendor and vendor != term:
                        suggestions.append(vendor.title())
                        break
                for product in self._product_index.keys():
                    if term in product and product != term:
                        suggestions.append(product.title())
                        break
        
        elif len(results) > 50:
            # Suggest more specific terms
            common_vendors = defaultdict(int)
            common_categories = defaultdict(int)
            
            for result in results[:20]:  # Look at top 20 results
                if result.get('vendor'):
                    common_vendors[result['vendor']] += 1
                for category in (result.get('categories') or []):
                    common_categories[category] += 1
            
            # Suggest adding vendor filter
            top_vendor = max(common_vendors.items(), key=lambda x: x[1])[0] if common_vendors else None
            if top_vendor:
                suggestions.append(f"{query} {top_vendor}")
            
            # Suggest adding category filter
            top_category = max(common_categories.items(), key=lambda x: x[1])[0] if common_categories else None
            if top_category:
                suggestions.append(f"{query} {top_category.replace('_', ' ')}")
        
        return suggestions[:5]  # Limit to 5 suggestions

    def get_cpe_by_id(self, cpe_name_id: str) -> Optional[Dict[str, Any]]:
        """Get specific CPE by name ID"""
        try:
            if cpe_name_id in self._cpe_name_index:
                idx = self._cpe_name_index[cpe_name_id]
                if idx < len(self.cpe_products):
                    product = self.cpe_products[idx]
                    product_dict = asdict(product)
                    
                    # Convert datetime objects
                    for field in ['last_modified', 'created', 'deprecation_date']:
                        if product_dict.get(field):
                            product_dict[field] = product_dict[field].isoformat()
                    
                    return product_dict
            return None
            
        except Exception as e:
            logger.error(f"Failed to get CPE by ID {cpe_name_id}: {e}")
            return None

    def get_categories(self, limit: int = 50) -> List[str]:
        """Get available categories"""
        categories = list(self._category_index.keys())
        categories.sort()
        return categories[:limit]

    def get_vendors(self, limit: int = 100) -> List[str]:
        """Get available vendors"""
        vendors = list(self._vendor_index.keys())
        vendors.sort()
        return [v.title() for v in vendors[:limit]]

    def get_search_suggestions(self, partial_query: str, limit: int = 10) -> List[str]:
        """Get search suggestions for autocomplete"""
        suggestions = []
        partial_lower = partial_query.lower()
        
        # Vendor suggestions
        for vendor in self._vendor_index.keys():
            if vendor.startswith(partial_lower):
                suggestions.append(vendor.title())
        
        # Product suggestions
        for product in self._product_index.keys():
            if product.startswith(partial_lower):
                suggestions.append(product.title())
        
        # Remove duplicates and sort
        suggestions = list(set(suggestions))
        suggestions.sort()
        
        return suggestions[:limit]

    def get_status(self) -> Dict[str, Any]:
        """Get CPE database status"""
        try:
            return {
                'has_data': len(self.cpe_products) > 0,
                'total_products': len(self.cpe_products),
                'total_matches': len(self.cpe_matches),
                'last_updated': self._get_cache_timestamp(),
                'cache_files': {
                    'dictionary_cache_exists': self.dictionary_cache_file.exists(),
                    'match_cache_exists': self.match_cache_file.exists(),
                    'enhanced_cache_exists': self.enhanced_cache_file.exists()
                },
                'categories_available': len(self._category_index),
                'vendors_count': len(self._vendor_index),
                'search_indices_built': bool(self._cpe_name_index)
            }
        except Exception as e:
            logger.error(f"Failed to get status: {e}")
            return {
                'has_data': False,
                'total_products': 0,
                'total_matches': 0,
                'error': str(e)
            }

    def _get_cache_timestamp(self) -> Optional[str]:
        """Get the timestamp of the most recent cache file"""
        timestamps = []
        
        for cache_file in [self.dictionary_cache_file, self.match_cache_file, self.enhanced_cache_file]:
            if cache_file.exists():
                mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
                timestamps.append(mtime)
        
        if timestamps:
            return max(timestamps).isoformat()
        return None

    def clear_cache(self) -> List[str]:
        """Clear all cache files"""
        removed_files = []
        
        for cache_file in [self.dictionary_cache_file, self.match_cache_file, self.enhanced_cache_file]:
            if cache_file.exists():
                cache_file.unlink()
                removed_files.append(str(cache_file))
        
        # Clear in-memory data
        self.cpe_products = []
        self.cpe_matches = []
        self._vendor_index = {}
        self._product_index = {}
        self._category_index = {}
        self._keyword_index = {}
        self._cpe_name_index = {}
        
        return removed_files

    def find_cpe_matches_for_product(self, vendor: str, product: str, version: str = None) -> List[CPEMatch]:
        """Find CPE matches for a specific product"""
        matches = []
        
        try:
            # Search for relevant CPE products first
            query = f"{vendor} {product}"
            search_result = self.enhanced_search(query, limit=50)
            
            # Find matching CPE entries
            for product_data in search_result.get('products', []):
                cpe_name = product_data.get('cpe_name', '')
                
                # Find corresponding matches
                for match in self.cpe_matches:
                    if self._cpe_matches_product(match, cpe_name, version):
                        matches.append(match)
            
            return matches
            
        except Exception as e:
            logger.error(f"Failed to find CPE matches: {e}")
            return []

    def _cpe_matches_product(self, match: CPEMatch, target_cpe: str, version: str = None) -> bool:
        """Check if CPE match applies to target product"""
        try:
            # Basic CPE name matching (without version)
            match_base = ':'.join(match.cpe_name.split(':')[:5]) + ':*'  # vendor:product without version
            target_base = ':'.join(target_cpe.split(':')[:5]) + ':*'
            
            if match_base != target_base:
                return False
            
            # If no version provided, return true for base match
            if not version:
                return True
            
            # Check version range constraints
            if match.has_version_range:
                return self._version_in_range(version, match)
            elif match.affects_all_versions:
                return True
            
            # Exact version match
            match_version = match.cpe_name.split(':')[5] if len(match.cpe_name.split(':')) > 5 else '*'
            return match_version == '*' or match_version == version
            
        except Exception as e:
            logger.error(f"Error checking CPE match: {e}")
            return False

    def _version_in_range(self, version: str, match: CPEMatch) -> bool:
        """Check if version falls within match range"""
        try:
            # Simple version comparison (can be enhanced with proper version parsing)
            version_parts = [int(x) for x in version.split('.') if x.isdigit()]
            
            if match.version_start_including:
                start_parts = [int(x) for x in match.version_start_including.split('.') if x.isdigit()]
                if version_parts < start_parts:
                    return False
            
            if match.version_start_excluding:
                start_parts = [int(x) for x in match.version_start_excluding.split('.') if x.isdigit()]
                if version_parts <= start_parts:
                    return False
            
            if match.version_end_including:
                end_parts = [int(x) for x in match.version_end_including.split('.') if x.isdigit()]
                if version_parts > end_parts:
                    return False
            
            if match.version_end_excluding:
                end_parts = [int(x) for x in match.version_end_excluding.split('.') if x.isdigit()]
                if version_parts >= end_parts:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Version range check failed: {e}")
            return True  # Default to include if parsing fails