"""
NIST CPE Database Ingestion Engine (Updated for Manual Lookup)
Focuses on data ingestion and search functionality, removes auto-categorization
app/services/nist_cpe_engine.py
"""

import asyncio
import json
import logging
import time
import gzip
import tarfile
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, text
import difflib
import hashlib
import httpx
from pathlib import Path
import tempfile
import os
import re

from app.core.database import get_db
from app.core.config import settings

logger = logging.getLogger(__name__)

@dataclass
class CPEProduct:
    """Structured CPE product information from JSON API"""
    cpe_name: str  # The CPE 2.3 formatted string
    cpe_name_id: str  # UUID from NIST
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
    titles: List[Dict[str, str]]  # Language-specific titles
    references: List[Dict[str, str]]  # References with URLs
    deprecated: bool
    deprecation_date: Optional[datetime]
    last_modified: datetime
    created: datetime

class CPEDatabaseManager:
    """Manages NIST CPE database ingestion and search functionality"""
    
    def __init__(self, db: Session):
        self.db = db
        # Updated URLs for bulk downloads
        self.cpe_dictionary_url = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"
        self.cpe_match_url = "https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.tar.gz"
        
        self.cache_dir = Path(settings.CPE_CACHE_DIR)
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_file = self.cache_dir / "cpe_products.json"
        self.temp_dir = self.cache_dir / "temp"
        self.temp_dir.mkdir(exist_ok=True)
        
        self.cpe_products: List[CPEProduct] = []
    
    async def download_cpe_bulk_file(self, url: str, filename: str) -> bool:
        """Download a bulk CPE file from NIST"""
        try:
            logger.info(f"Downloading {filename} from {url}")
            
            async with httpx.AsyncClient(timeout=300.0) as client:
                response = await client.get(url)
                response.raise_for_status()
                
                file_path = self.temp_dir / filename
                with open(file_path, 'wb') as f:
                    f.write(response.content)
                
                logger.info(f"Downloaded {filename} ({len(response.content)} bytes)")
                return True
                
        except Exception as e:
            logger.error(f"Failed to download {filename}: {e}")
            return False
    
    def extract_and_parse_cpe_files(self) -> List[CPEProduct]:
        """Extract and parse CPE files from downloaded archives"""
        all_products = []
        
        try:
            # Process CPE Dictionary
            cpe_dict_file = self.temp_dir / "nvdcpe-2.0.tar.gz"
            if cpe_dict_file.exists():
                logger.info("Processing CPE Dictionary...")
                products = self._process_cpe_archive(cpe_dict_file, is_dictionary=True)
                all_products.extend(products)
                logger.info(f"Processed {len(products)} products from CPE Dictionary")
            
            return all_products
            
        except Exception as e:
            logger.error(f"Failed to extract and parse CPE files: {e}")
            return []
    
    def _process_cpe_archive(self, archive_path: Path, is_dictionary: bool = True) -> List[CPEProduct]:
        """Process a CPE archive (tar.gz) and extract products"""
        products = []
        
        try:
            with tarfile.open(archive_path, 'r:gz') as tar:
                for member in tar.getmembers():
                    if member.isfile() and member.name.endswith('.json'):
                        logger.info(f"Processing {member.name}")
                        
                        # Extract and read JSON file
                        json_file = tar.extractfile(member)
                        if json_file:
                            json_data = json.load(json_file)
                            
                            if is_dictionary:
                                # Process CPE Dictionary format
                                cpe_items = json_data.get('products', [])
                                for item in cpe_items:
                                    product = self._parse_cpe_product_from_dict(item)
                                    if product and self._is_relevant_product(product):
                                        products.append(product)
            
            return products
            
        except Exception as e:
            logger.error(f"Error processing archive {archive_path}: {e}")
            return []
    
    def _parse_cpe_product_from_dict(self, product_data: Dict) -> Optional[CPEProduct]:
        """Parse CPE product from dictionary JSON format"""
        try:
            cpe_data = product_data.get('cpe', {})
            cpe_name = cpe_data.get('cpeName', '')
            
            if not cpe_name:
                return None
            
            # Parse CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
            cpe_parts = cpe_name.split(':')
            if len(cpe_parts) < 13:
                return None
            
            # Parse dates
            last_modified = None
            created = None
            
            if product_data.get('lastModified'):
                try:
                    last_modified = datetime.fromisoformat(product_data['lastModified'].replace('Z', '+00:00'))
                except:
                    pass
            
            if product_data.get('created'):
                try:
                    created = datetime.fromisoformat(product_data['created'].replace('Z', '+00:00'))
                except:
                    pass
            
            # Handle deprecation
            deprecated = cpe_data.get('deprecated', False)
            deprecation_date = None
            if deprecated and cpe_data.get('deprecationDate'):
                try:
                    deprecation_date = datetime.fromisoformat(cpe_data['deprecationDate'].replace('Z', '+00:00'))
                except:
                    pass
            
            return CPEProduct(
                cpe_name=cpe_name,
                cpe_name_id=product_data.get('cpeNameId', ''),
                vendor=cpe_parts[3] if len(cpe_parts) > 3 else '',
                product=cpe_parts[4] if len(cpe_parts) > 4 else '',
                version=cpe_parts[5] if len(cpe_parts) > 5 else '*',
                update=cpe_parts[6] if len(cpe_parts) > 6 else '*',
                edition=cpe_parts[7] if len(cpe_parts) > 7 else '*',
                language=cpe_parts[8] if len(cpe_parts) > 8 else '*',
                sw_edition=cpe_parts[9] if len(cpe_parts) > 9 else '*',
                target_sw=cpe_parts[10] if len(cpe_parts) > 10 else '*',
                target_hw=cpe_parts[11] if len(cpe_parts) > 11 else '*',
                other=cpe_parts[12] if len(cpe_parts) > 12 else '*',
                titles=cpe_data.get('titles', []),
                references=cpe_data.get('refs', []),
                deprecated=deprecated,
                deprecation_date=deprecation_date,
                last_modified=last_modified or datetime.now(),
                created=created or datetime.now()
            )
            
        except Exception as e:
            logger.debug(f"Error parsing CPE product: {e}")
            return None
    
    async def download_all_cpe_data(self) -> bool:
        """Download all CPE data from NIST bulk files"""
        try:
            logger.info("Starting NIST CPE bulk data download...")
            
            # Clean temp directory
            for file in self.temp_dir.glob("*"):
                file.unlink()
            
            # Download CPE Dictionary (primary source)
            dict_success = await self.download_cpe_bulk_file(
                self.cpe_dictionary_url, 
                "nvdcpe-2.0.tar.gz"
            )
            
            if not dict_success:
                logger.error("Failed to download CPE Dictionary")
                return False
            
            # Extract and parse files
            all_products = self.extract_and_parse_cpe_files()
            
            if not all_products:
                logger.error("No products extracted from CPE files")
                return False
            
            # Cache the results
            cache_data = {
                'download_date': datetime.now().isoformat(),
                'total_products': len(all_products),
                'source': 'NIST Bulk JSON Downloads',
                'dictionary_url': self.cpe_dictionary_url,
                'products': [asdict(product) for product in all_products]
            }
            
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2, default=str)
            
            self.cpe_products = all_products
            logger.info(f"Downloaded and cached {len(all_products)} relevant CPE products")
            
            # Clean up temp files
            for file in self.temp_dir.glob("*"):
                file.unlink()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to download CPE data: {e}")
            return False
    
    def load_cached_cpe_data(self) -> bool:
        """Load CPE data from local cache if available and fresh"""
        try:
            if not self.cache_file.exists():
                return False
            
            # Check cache age
            cache_age = datetime.now() - datetime.fromtimestamp(self.cache_file.stat().st_mtime)
            if cache_age > timedelta(hours=settings.CPE_CACHE_EXPIRY_HOURS):
                logger.info("CPE cache is stale, will refresh")
                return False
            
            with open(self.cache_file, 'r') as f:
                cache_data = json.load(f)
            
            # Reconstruct CPEProduct objects
            products = []
            for product_dict in cache_data.get('products', []):
                # Convert string dates back to datetime objects
                if product_dict.get('last_modified'):
                    try:
                        product_dict['last_modified'] = datetime.fromisoformat(product_dict['last_modified'])
                    except:
                        product_dict['last_modified'] = datetime.now()
                
                if product_dict.get('created'):
                    try:
                        product_dict['created'] = datetime.fromisoformat(product_dict['created'])
                    except:
                        product_dict['created'] = datetime.now()
                
                if product_dict.get('deprecation_date'):
                    try:
                        product_dict['deprecation_date'] = datetime.fromisoformat(product_dict['deprecation_date'])
                    except:
                        product_dict['deprecation_date'] = None
                
                products.append(CPEProduct(**product_dict))
            
            self.cpe_products = products
            logger.info(f"Loaded {len(products)} CPE products from cache")
            logger.info(f"Cache source: {cache_data.get('source', 'Unknown')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load cached CPE data: {e}")
            return False
    
    def _is_relevant_product(self, product: CPEProduct) -> bool:
        """Filter to only include relevant products"""
        # Skip deprecated products unless configured otherwise
        if product.deprecated and not settings.CPE_INCLUDE_DEPRECATED:
            return False
        
        # Skip generic or placeholder entries
        if product.vendor in ['*', '-'] or product.product in ['*', '-']:
            return False
        
        # Focus on application software (part 'a')
        if not product.cpe_name.startswith('cpe:2.3:a:'):
            return False
        
        # Filter for common enterprise software categories
        product_lower = product.product.lower()
        vendor_lower = product.vendor.lower()
        
        # Get English title for additional filtering
        english_title = ''
        for title in product.titles:
            if title.get('lang') == 'en':
                english_title = title.get('title', '').lower()
                break
        
        relevant_keywords = [
            'server', 'database', 'web', 'http', 'sql', 'cache', 'proxy',
            'load', 'balancer', 'monitoring', 'security', 'firewall',
            'container', 'docker', 'kubernetes', 'message', 'queue',
            'search', 'index', 'analytics', 'log', 'api', 'gateway',
            'framework', 'runtime', 'platform', 'service', 'daemon',
            'engine', 'manager', 'agent', 'client', 'tool'
        ]
        
        return any(keyword in product_lower or keyword in vendor_lower or keyword in english_title
                  for keyword in relevant_keywords)
    
    # New search functionality for manual lookup
    def search_products(self, query: str, vendor_filter: Optional[str] = None, 
                       product_filter: Optional[str] = None, version_filter: Optional[str] = None,
                       include_deprecated: bool = False, limit: int = 50, 
                       offset: int = 0) -> Tuple[List[CPEProduct], int]:
        """Search CPE products with filters"""
        if not self.cpe_products:
            return [], 0
        
        query_lower = query.lower().strip()
        results = []
        
        for product in self.cpe_products:
            # Skip deprecated if not included
            if product.deprecated and not include_deprecated:
                continue
            
            # Apply filters
            if vendor_filter and vendor_filter.lower() not in product.vendor.lower():
                continue
            
            if product_filter and product_filter.lower() not in product.product.lower():
                continue
            
            if version_filter and version_filter.lower() not in product.version.lower():
                continue
            
            # Search in relevant fields
            searchable_text = ' '.join([
                product.vendor,
                product.product,
                product.version,
                product.cpe_name,
                ' '.join([title.get('title', '') for title in product.titles if title.get('lang') == 'en'])
            ]).lower()
            
            if query_lower in searchable_text:
                results.append(product)
        
        # Sort by relevance (exact matches first, then partial matches)
        def relevance_score(product):
            score = 0
            query_words = query_lower.split()
            
            for word in query_words:
                if word in product.vendor.lower():
                    score += 10
                if word in product.product.lower():
                    score += 10
                if word == product.vendor.lower():
                    score += 20
                if word == product.product.lower():
                    score += 20
            
            # Boost score for non-deprecated products
            if not product.deprecated:
                score += 5
            
            # Boost score for recent updates
            if product.last_modified and (datetime.now() - product.last_modified).days < 365:
                score += 3
            
            return score
        
        results.sort(key=relevance_score, reverse=True)
        
        total_count = len(results)
        paginated_results = results[offset:offset + limit]
        
        return paginated_results, total_count
    
    def get_product_by_id(self, cpe_name_id: str) -> Optional[CPEProduct]:
        """Get a specific CPE product by its ID"""
        for product in self.cpe_products:
            if product.cpe_name_id == cpe_name_id:
                return product
        return None
    
    def get_vendors(self, query: Optional[str] = None, limit: int = 50) -> List[str]:
        """Get list of vendors for filtering"""
        vendors = set()
        
        for product in self.cpe_products:
            if not product.deprecated or settings.CPE_INCLUDE_DEPRECATED:
                vendors.add(product.vendor)
        
        vendor_list = list(vendors)
        
        if query:
            query_lower = query.lower()
            vendor_list = [v for v in vendor_list if query_lower in v.lower()]
        
        vendor_list.sort()
        return vendor_list[:limit]
    
    def get_products_by_vendor(self, vendor: str, limit: int = 100) -> List[CPEProduct]:
        """Get products for a specific vendor"""
        results = []
        vendor_lower = vendor.lower()
        
        for product in self.cpe_products:
            if product.vendor.lower() == vendor_lower:
                if not product.deprecated or settings.CPE_INCLUDE_DEPRECATED:
                    results.append(product)
        
        return results[:limit]
    
    def get_product_versions(self, vendor: str, product_name: str) -> List[str]:
        """Get available versions for a specific vendor/product combination"""
        versions = set()
        vendor_lower = vendor.lower()
        product_lower = product_name.lower()
        
        for product in self.cpe_products:
            if (product.vendor.lower() == vendor_lower and 
                product.product.lower() == product_lower and 
                product.version not in ['*', '-', '']):
                versions.add(product.version)
        
        # Sort versions (attempt semantic version sorting)
        version_list = list(versions)
        try:
            from packaging import version as pkg_version
            version_list.sort(key=lambda x: pkg_version.Version(x), reverse=True)
        except:
            version_list.sort(reverse=True)
        
        return version_list
    
    async def _cleanup_old_auto_categorized_data(self):
        """
        Clean up any old auto-categorized service data that might remain from previous implementations.
        This is a compatibility method to prevent errors during CPE data ingestion.
        """
        try:
            logger.info("Performing cleanup of old auto-categorized data...")
            
            # This method was used in a previous implementation to clean up 
            # automatically categorized service data. Since you've moved away
            # from that approach, this is now just a placeholder to prevent errors.
            
            # If you have any old service-related data that needs cleanup, 
            # you can add those operations here. For now, we'll just log and continue.
            
            logger.info("Cleanup completed (no action needed in current implementation)")
            
        except Exception as e:
            # Don't let cleanup failures stop the CPE ingestion
            logger.warning(f"Cleanup method encountered an error (non-critical): {e}")
            pass
    
    async def run_full_ingestion(self) -> Dict[str, any]:
        """Run complete CPE ingestion process - LOOKUP ONLY (no auto-categorization)"""
        stats = {
            'download_success': False,
            'products_parsed': 0,
            'total_products': 0,
            'lookup_ready': False,
            'errors': []
        }
        
        try:
            # Try to load from cache first
            if self.load_cached_cpe_data():
                logger.info("Using cached CPE data from bulk downloads")
                stats['download_success'] = True
                stats['products_parsed'] = len(self.cpe_products)
                stats['total_products'] = len(self.cpe_products)
                stats['lookup_ready'] = True
            else:
                # Download fresh data
                stats['download_success'] = await self.download_all_cpe_data()
                
                if not stats['download_success']:
                    stats['errors'].append("Failed to download CPE bulk data")
                    return stats
                
                stats['products_parsed'] = len(self.cpe_products)
                stats['total_products'] = len(self.cpe_products)
                stats['lookup_ready'] = len(self.cpe_products) > 0
            
            if not self.cpe_products:
                stats['errors'].append("No relevant products found in CPE data")
                return stats
            
            # Log success but don't create any database entries automatically
            logger.info(f"CPE ingestion completed successfully with {len(self.cpe_products)} products available for lookup")
            logger.info("CPE data is ready for manual service creation lookups")
            
            # Remove any old auto-categorization artifacts that might remain
            # This is optional cleanup in case there's old data
            await self._cleanup_old_auto_categorized_data()
            
        except Exception as e:
            logger.error(f"CPE ingestion failed: {e}")
            stats['errors'].append(f"Ingestion failed: {e}")
        
        return stats
    
# Add this to the CPEDatabaseManager class if missing:
def get_product_by_id(self, cpe_name_id: str) -> Optional[CPEProduct]:
    """Get a specific CPE product by its ID"""
    for product in self.cpe_products:
        if product.cpe_name_id == cpe_name_id:
            return product
    return None

def get_vendors(self, query: Optional[str] = None, limit: int = 50) -> List[str]:
    """Get list of vendors for filtering"""
    vendors = set()
    
    for product in self.cpe_products:
        if not product.deprecated or settings.CPE_INCLUDE_DEPRECATED:
            vendors.add(product.vendor)
    
    vendor_list = list(vendors)
    
    if query:
        query_lower = query.lower()
        vendor_list = [v for v in vendor_list if query_lower in v.lower()]
    
    vendor_list.sort()
    return vendor_list[:limit]

def _preprocess_search_query(self, query: str) -> str:
    """
    Preprocess and normalize search query for better matching
    
    Examples:
    - "windows 11" -> handles OS version properly
    - "apache 2.4" -> handles software version
    - "mysql server" -> handles product variants
    """
    if not query:
        return ""
    
    query = query.lower().strip()
    
    # Handle common OS version patterns
    os_patterns = [
        # Windows versions
        (r'\bwindows\s+11\b', 'windows 11 microsoft'),
        (r'\bwindows\s+10\b', 'windows 10 microsoft'),
        (r'\bwin\s*11\b', 'windows 11 microsoft'),
        (r'\bwin\s*10\b', 'windows 10 microsoft'),
        (r'\bwindows\s+server\s+(\d{4})', r'windows server \1 microsoft'),
        
        # Linux distributions
        (r'\bubuntu\s+(\d+\.?\d*)', r'ubuntu \1 canonical'),
        (r'\bcentos\s+(\d+)', r'centos \1 centos'),
        (r'\brhel\s+(\d+)', r'red hat enterprise linux \1'),
        
        # Common software patterns
        (r'\bmysql\s+(\d+\.?\d*)', r'mysql \1 oracle'),
        (r'\bapache\s+(\d+\.?\d*)', r'apache http server \1'),
        (r'\bnginx\s+(\d+\.?\d*)', r'nginx \1'),
        (r'\bpostgresql\s+(\d+\.?\d*)', r'postgresql \1'),
    ]
    
    # Apply pattern replacements
    for pattern, replacement in os_patterns:
        query = re.sub(pattern, replacement, query)
    
    return query

def _matches_filter(self, field_value: str, filter_value: str) -> bool:
    """Check if field value matches filter (case-insensitive partial match)"""
    if not field_value or not filter_value:
        return True
    return filter_value.lower() in field_value.lower()

def _matches_search_query(self, product: 'CPEProduct', normalized_query: str, original_query: str) -> Dict:
    """
    Check if product matches search query with detailed scoring
    
    Returns:
        Dict with 'matches' (bool), 'score' (float), and 'details' (dict)
    """
    
    # Build comprehensive searchable text
    searchable_fields = {
        'vendor': product.vendor.lower(),
        'product': product.product.lower(), 
        'version': product.version.lower(),
        'cpe_name': product.cpe_name.lower(),
        'titles': self._get_english_titles(product).lower()
    }
    
    # Combine all searchable text
    all_searchable_text = ' '.join(searchable_fields.values())
    
    # Split query into individual terms
    query_terms = normalized_query.split()
    original_terms = original_query.lower().split()
    all_terms = list(set(query_terms + original_terms))
    
    # Calculate match score
    total_score = 0
    match_details = {
        'exact_matches': [],
        'partial_matches': [],
        'field_matches': {},
        'version_match': False
    }
    
    for term in all_terms:
        if len(term) < 2:  # Skip very short terms
            continue
            
        term_score = 0
        
        # Check each field for matches
        for field_name, field_value in searchable_fields.items():
            if term in field_value:
                field_score = self._calculate_field_score(term, field_value, field_name)
                term_score += field_score
                match_details['field_matches'][field_name] = match_details['field_matches'].get(field_name, 0) + field_score
                
                if term == field_value.strip():  # Exact field match
                    match_details['exact_matches'].append((field_name, term))
                else:  # Partial field match
                    match_details['partial_matches'].append((field_name, term))
        
        # Special handling for version numbers
        if self._looks_like_version(term):
            if self._version_matches(term, product.version):
                term_score += 15  # Boost for version matches
                match_details['version_match'] = True
        
        total_score += term_score
    
    # Apply relevance boosts
    total_score += self._apply_relevance_boosts(product, match_details)
    
    # A product matches if it has any term matches
    matches = total_score > 0
    
    return {
        'matches': matches,
        'score': total_score,
        'details': match_details
    }

def _get_english_titles(self, product: 'CPEProduct') -> str:
    """Extract English titles from product"""
    titles = []
    for title in product.titles:
        if title.get('lang') == 'en' and title.get('title'):
            titles.append(title['title'])
    return ' '.join(titles)

def _calculate_field_score(self, term: str, field_value: str, field_name: str) -> float:
    """Calculate score for term match in specific field"""
    
    # Field importance weights
    field_weights = {
        'vendor': 12,
        'product': 15,
        'version': 8,
        'cpe_name': 5,
        'titles': 10
    }
    
    base_weight = field_weights.get(field_name, 5)
    
    # Exact vs partial match scoring
    if term == field_value.strip():
        return base_weight * 2  # Exact match bonus
    elif field_value.startswith(term):
        return base_weight * 1.5  # Prefix match bonus  
    elif term in field_value:
        return base_weight  # Partial match
    
    return 0

def _looks_like_version(self, term: str) -> bool:
    """Check if term looks like a version number"""
    version_patterns = [
        r'^\d+$',                    # 11, 10
        r'^\d+\.\d+$',              # 2.4, 11.0
        r'^\d+\.\d+\.\d+$',         # 2.4.1
        r'^\d+\.\d+\.\d+\.\d+$',    # 1.2.3.4
        r'^\d{4}$',                 # 2019, 2022 (for Windows Server, etc.)
        r'^\d+[hH]\d+$',            # 21H2, 22H2 (Windows versions)
    ]
    
    return any(re.match(pattern, term) for pattern in version_patterns)

def _version_matches(self, search_version: str, product_version: str) -> bool:
    """Check if search version matches product version"""
    if not search_version or not product_version or product_version == '*':
        return False
    
    search_version = search_version.lower()
    product_version = product_version.lower()
    
    # Direct match
    if search_version == product_version:
        return True
    
    # Version contained in product version
    if search_version in product_version:
        return True
    
    # Handle Windows version patterns
    if search_version in ['11', '10'] and 'windows' in product_version:
        # Look for Windows 11, Windows 10 patterns
        windows_patterns = [
            rf'\b{search_version}\b',           # Exact version boundary
            rf'\b{search_version}\.0\b',        # Version.0 pattern
            rf'windows.*{search_version}',      # Windows ... version
        ]
        return any(re.search(pattern, product_version) for pattern in windows_patterns)
    
    return False

def _apply_relevance_boosts(self, product: 'CPEProduct', match_details: Dict) -> float:
    """Apply additional relevance boosts based on product characteristics"""
    boost = 0
    
    # Boost for non-deprecated products
    if not product.deprecated:
        boost += 5
    
    # Boost for recently updated products
    if product.last_modified:
        days_since_update = (datetime.now() - product.last_modified).days
        if days_since_update < 365:
            boost += 3
        elif days_since_update < 730:
            boost += 1
    
    # Boost for exact field matches
    boost += len(match_details.get('exact_matches', [])) * 5
    
    # Boost for version matches
    if match_details.get('version_match'):
        boost += 8
    
    # Boost for multiple field matches (indicates comprehensive match)
    field_match_count = len([f for f, score in match_details.get('field_matches', {}).items() if score > 0])
    if field_match_count >= 3:
        boost += 10
    elif field_match_count >= 2:
        boost += 5
    
    return boost

# Additional helper method to add to the CPEDatabaseManager class
def debug_search_query(self, query: str, limit: int = 5) -> Dict:
    """
    Debug search functionality by showing detailed matching process
    Useful for troubleshooting why searches don't return expected results
    """
    logger.info(f"=== DEBUG SEARCH: '{query}' ===")
    
    if not self.cpe_products:
        return {"error": "No CPE products loaded"}
    
    normalized_query = self._preprocess_search_query(query.strip())
    logger.info(f"Normalized query: '{normalized_query}'")
    
    debug_results = []
    
    # Test with first few products for debugging
    sample_products = self.cpe_products[:100]  # Test with sample
    
    for product in sample_products:
        if product.deprecated:
            continue
            
        match_result = self._matches_search_query(product, normalized_query, query)
        
        if match_result['matches']:
            debug_info = {
                'cpe_name': product.cpe_name,
                'vendor': product.vendor,
                'product': product.product,
                'version': product.version,
                'score': match_result['score'],
                'match_details': match_result['details']
            }
            debug_results.append(debug_info)
    
    # Sort by score
    debug_results.sort(key=lambda x: x['score'], reverse=True)
    
    result = {
        'query': query,
        'normalized_query': normalized_query,
        'total_matches': len(debug_results),
        'top_matches': debug_results[:limit],
        'sample_size': len(sample_products)
    }
    
    logger.info(f"Debug results: {result}")
    return result

def search_products(self, query: str, vendor_filter: Optional[str] = None, 
                   product_filter: Optional[str] = None, version_filter: Optional[str] = None,
                   include_deprecated: bool = False, limit: int = 50, 
                   offset: int = 0) -> Tuple[List[CPEProduct], int]:
    """
    Enhanced search CPE products with better matching logic
    
    FIXES:
    1. Improved query preprocessing (handles "windows 11", "apache 2.4", etc.)
    2. Better searchable text construction
    3. Multi-word query handling
    4. Fuzzy version matching
    5. Smart OS version detection
    """
    if not self.cpe_products:
        return [], 0
    
    # Preprocess and normalize query
    query_normalized = self._preprocess_search_query(query.strip())
    if not query_normalized:
        return [], 0
        
    logger.info(f"Searching CPE products: '{query}' -> normalized: '{query_normalized}'")
    
    results = []
    
    for product in self.cpe_products:
        # Skip deprecated if not included
        if product.deprecated and not include_deprecated:
            continue
        
        # Apply vendor filter
        if vendor_filter and not self._matches_filter(product.vendor, vendor_filter):
            continue
        
        # Apply product filter  
        if product_filter and not self._matches_filter(product.product, product_filter):
            continue
        
        # Apply version filter
        if version_filter and not self._matches_filter(product.version, version_filter):
            continue
        
        # Check if product matches the search query
        match_result = self._matches_search_query(product, query_normalized, query)
        if match_result['matches']:
            # Add match score to product for sorting
            product._search_score = match_result['score']
            product._match_details = match_result['details']
            results.append(product)
    
    logger.info(f"Found {len(results)} products matching search criteria")
    
    # Sort by relevance score (highest first)
    results.sort(key=lambda p: getattr(p, '_search_score', 0), reverse=True)
    
    total_count = len(results)
    paginated_results = results[offset:offset + limit]
    
    return paginated_results, total_count
    
    # Sort by relevance (exact matches first, then partial matches)
    def relevance_score(product):
        score = 0
        query_words = query_lower.split()
        
        for word in query_words:
            if word in product.vendor.lower():
                score += 10
            if word in product.product.lower():
                score += 10
            if word == product.vendor.lower():
                score += 20
            if word == product.product.lower():
                score += 20
        
        # Boost score for non-deprecated products
        if not product.deprecated:
            score += 5
        
        # Boost score for recent updates
        if product.last_modified and (datetime.now() - product.last_modified).days < 365:
            score += 3
        
        return score
    
    results.sort(key=relevance_score, reverse=True)
    
    total_count = len(results)
    paginated_results = results[offset:offset + limit]
    
    return paginated_results, total_count

# Module-level utility functions
async def refresh_cpe_data(db: Session) -> Dict[str, any]:
    """Utility function to refresh CPE data"""
    cpe_manager = CPEDatabaseManager(db)
    return await cpe_manager.run_full_ingestion()


def check_cpe_data_freshness(db: Session) -> Dict[str, any]:
    """Check if CPE data needs refreshing"""
    cpe_manager = CPEDatabaseManager(db)
    cache_file = cpe_manager.cache_file
    
    if not cache_file.exists():
        return {
            'has_data': False,
            'needs_refresh': True,
            'reason': 'No cached data found'
        }
    
    cache_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
    # Use settings if available, otherwise default to 24 hours
    try:
        expiry_hours = settings.CPE_CACHE_EXPIRY_HOURS
    except AttributeError:
        expiry_hours = 24
    
    needs_refresh = cache_age > timedelta(hours=expiry_hours)
    
    return {
        'has_data': True,
        'needs_refresh': needs_refresh,
        'cache_age_hours': cache_age.total_seconds() / 3600,
        'reason': 'Cache is stale' if needs_refresh else 'Cache is fresh'
    }