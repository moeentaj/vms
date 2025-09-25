"""
Enhanced CPE Engine - app/services/enhanced_cpe_engine.py
Complete replacement for your CPE engine with advanced search capabilities.
"""

import asyncio
import json
import logging
import time
import gzip
import re
import httpx
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from urllib.parse import unquote
import tempfile

from app.models.cpe import CPEProduct, CPETitle, CPEReference
from app.core.config import settings
from app.core.database import get_db

logger = logging.getLogger(__name__)

class EnhancedCPEDatabaseManager:
    """Enhanced CPE database manager with metadata-rich search capabilities"""
    
    def __init__(self, db: Session):
        self.db = db
        self.cpe_products: List[CPEProduct] = []
        
        # NIST data URLs
        self.cpe_dictionary_url = "https://nvd.nist.gov/feeds/json/cpe/1.0/nvdcpe-1.0-modified.json.gz"
        self.cpe_bulk_url = "https://nvd.nist.gov/feeds/json/cpe/1.0/nvdcpe-1.0-2023.json.gz"
        
        # Cache configuration
        self.cache_dir = Path(getattr(settings, 'CPE_CACHE_DIR', './cache'))
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_file = self.cache_dir / "enhanced_cpe_products.json"
        
        # Search optimization
        self._vendor_index = {}
        self._category_index = {}
        self._keyword_index = {}
    
    async def ingest_cpe_data(self, force_refresh: bool = False) -> Dict[str, any]:
        """
        Ingest CPE data with enhanced metadata extraction
        """
        stats = {
            'started_at': datetime.now().isoformat(),
            'products_processed': 0,
            'products_loaded': 0,
            'errors': [],
            'warnings': [],
            'categories_found': set(),
            'vendors_found': set(),
        }
        
        try:
            logger.info("Starting enhanced CPE data ingestion")
            
            # Download and process CPE data
            cpe_data = await self._download_cpe_data(force_refresh)
            if not cpe_data:
                stats['errors'].append("Failed to download CPE data")
                return stats
            
            # Process each CPE product with enhanced metadata
            products = []
            
            for product_data in cpe_data.get('CPE_Items', []):
                stats['products_processed'] += 1
                
                try:
                    enhanced_product = self._parse_enhanced_cpe_product(product_data)
                    if enhanced_product and self._is_relevant_product(enhanced_product):
                        products.append(enhanced_product)
                        stats['products_loaded'] += 1
                        
                        # Track statistics
                        stats['vendors_found'].add(enhanced_product.vendor)
                        stats['categories_found'].update(enhanced_product.categories)
                        
                except Exception as e:
                    stats['warnings'].append(f"Failed to process product: {e}")
                    logger.warning(f"Failed to process CPE product: {e}")
            
            self.cpe_products = products
            
            # Build search indices
            self._build_search_indices()
            
            # Cache the results
            await self._cache_products()
            
            # Convert sets to lists for JSON serialization
            stats['categories_found'] = list(stats['categories_found'])
            stats['vendors_found'] = list(stats['vendors_found'])
            
            stats['completed_at'] = datetime.now().isoformat()
            
            logger.info(f"Enhanced CPE ingestion completed: {stats['products_loaded']} products loaded")
            
        except Exception as e:
            logger.error(f"CPE ingestion failed: {e}")
            stats['errors'].append(f"Ingestion failed: {str(e)}")
        
        return stats
    
    async def _download_cpe_data(self, force_refresh: bool) -> Optional[Dict]:
        """Download CPE data from NIST"""
        
        cache_file = self.cache_dir / "raw_cpe_data.json"
        
        # Check cache freshness
        if not force_refresh and cache_file.exists():
            file_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
            if file_age < timedelta(hours=24):
                logger.info("Using cached CPE data")
                with open(cache_file, 'r') as f:
                    return json.load(f)
        
        logger.info("Downloading fresh CPE data from NIST")
        
        try:
            async with httpx.AsyncClient(timeout=300.0) as client:
                # Try modified feed first (smaller, recent changes)
                try:
                    response = await client.get(self.cpe_dictionary_url)
                    response.raise_for_status()
                except:
                    # Fallback to bulk feed
                    logger.info("Modified feed failed, trying bulk feed")
                    response = await client.get(self.cpe_bulk_url)
                    response.raise_for_status()
                
                # Decompress and parse JSON
                raw_data = gzip.decompress(response.content)
                cpe_data = json.loads(raw_data.decode('utf-8'))
                
                # Cache for future use
                with open(cache_file, 'w') as f:
                    json.dump(cpe_data, f)
                
                logger.info(f"Downloaded {len(cpe_data.get('CPE_Items', []))} CPE items")
                return cpe_data
                
        except Exception as e:
            logger.error(f"Failed to download CPE data: {e}")
            return None
    
    def _parse_enhanced_cpe_product(self, product_data: Dict) -> Optional[CPEProduct]:
        """Parse CPE product with enhanced metadata extraction"""
        
        try:
            cpe_data = product_data.get('cpe23Uri', '')
            if not cpe_data:
                # Try legacy format
                cpe_obj = product_data.get('cpe', {})
                cpe_data = cpe_obj.get('cpe23Uri', '')
            
            if not cpe_data:
                return None
            
            # Parse CPE 2.3 format
            cpe_parts = cpe_data.split(':')
            if len(cpe_parts) < 6:
                return None
            
            # Extract and normalize components
            vendor = self._normalize_cpe_component(cpe_parts[3])
            product = self._normalize_cpe_component(cpe_parts[4])
            version = self._normalize_cpe_component(cpe_parts[5]) if len(cpe_parts) > 5 else '*'
            
            # Parse enhanced titles
            titles = self._parse_titles(product_data)
            
            # Parse references
            references = self._parse_references(product_data)
            
            # Extract timestamps
            last_modified = self._parse_timestamp(product_data.get('lastModified'))
            created = self._parse_timestamp(product_data.get('created'))
            
            # Handle deprecation
            deprecated = product_data.get('deprecated', False)
            deprecation_date = None
            deprecated_by = []
            
            if deprecated:
                deprecation_date = self._parse_timestamp(product_data.get('deprecationDate'))
                # Extract deprecated_by information if available
                if 'deprecatedBy' in product_data:
                    dep_info = product_data['deprecatedBy']
                    if isinstance(dep_info, list):
                        deprecated_by = [item.get('cpe23Uri', '') for item in dep_info if 'cpe23Uri' in item]
                    elif isinstance(dep_info, str):
                        deprecated_by = [dep_info]
            
            return CPEProduct(
                cpe_name=cpe_data,
                cpe_name_id=product_data.get('cpeNameId', ''),
                vendor=vendor,
                product=product,
                version=version,
                update=self._normalize_cpe_component(cpe_parts[6]) if len(cpe_parts) > 6 else '*',
                edition=self._normalize_cpe_component(cpe_parts[7]) if len(cpe_parts) > 7 else '*',
                language=self._normalize_cpe_component(cpe_parts[8]) if len(cpe_parts) > 8 else '*',
                sw_edition=self._normalize_cpe_component(cpe_parts[9]) if len(cpe_parts) > 9 else '*',
                target_sw=self._normalize_cpe_component(cpe_parts[10]) if len(cpe_parts) > 10 else '*',
                target_hw=self._normalize_cpe_component(cpe_parts[11]) if len(cpe_parts) > 11 else '*',
                other=self._normalize_cpe_component(cpe_parts[12]) if len(cpe_parts) > 12 else '*',
                titles=titles,
                references=references,
                deprecated=deprecated,
                deprecation_date=deprecation_date,
                deprecated_by=deprecated_by,
                last_modified=last_modified,
                created=created,
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse CPE product: {e}")
            return None
    
    def _parse_titles(self, product_data: Dict) -> List[CPETitle]:
        """Parse title information with enhanced metadata"""
        titles = []
        
        # Check various title locations in NIST data
        title_sources = [
            product_data.get('titles', []),
            product_data.get('cpe', {}).get('titles', []),
        ]
        
        for title_list in title_sources:
            if isinstance(title_list, list):
                for title_item in title_list:
                    if isinstance(title_item, dict):
                        title_text = title_item.get('title', '').strip()
                        language = title_item.get('lang', 'en')
                        
                        if title_text:
                            titles.append(CPETitle(
                                title=title_text,
                                lang=language
                            ))
        
        # If no titles found, create a synthetic one
        if not titles:
            # Try to get from CPE components
            vendor = self._normalize_cpe_component(product_data.get('cpe23Uri', '').split(':')[3] if ':' in product_data.get('cpe23Uri', '') else '')
            product = self._normalize_cpe_component(product_data.get('cpe23Uri', '').split(':')[4] if ':' in product_data.get('cpe23Uri', '') else '')
            
            if vendor and product:
                synthetic_title = f"{vendor.title()} {product.replace('_', ' ').title()}"
                titles.append(CPETitle(title=synthetic_title, lang='en'))
        
        return titles
    
    def _parse_references(self, product_data: Dict) -> List[CPEReference]:
        """Parse reference information"""
        references = []
        
        # Check various reference locations
        ref_sources = [
            product_data.get('refs', []),
            product_data.get('references', []),
            product_data.get('cpe', {}).get('refs', []),
        ]
        
        for ref_list in ref_sources:
            if isinstance(ref_list, list):
                for ref_item in ref_list:
                    if isinstance(ref_item, dict):
                        href = ref_item.get('ref', ref_item.get('href', '')).strip()
                        ref_type = ref_item.get('type', '').strip()
                        
                        if href:
                            # Try to extract meaningful content from reference
                            content = self._extract_reference_content(ref_item, href)
                            
                            references.append(CPEReference(
                                href=href,
                                ref_type=ref_type,
                                content=content
                            ))
        
        return references
    
    def _extract_reference_content(self, ref_item: Dict, href: str) -> Optional[str]:
        """Extract meaningful content from reference"""
        
        # Direct content fields
        content_fields = ['content', 'text', 'description', 'title']
        for field in content_fields:
            if field in ref_item and ref_item[field]:
                return ref_item[field].strip()
        
        # Infer content from URL
        if href:
            href_lower = href.lower()
            
            if 'cve' in href_lower:
                return "Security vulnerability information"
            elif 'advisory' in href_lower or 'security' in href_lower:
                return "Security advisory"
            elif 'vendor' in href_lower or 'product' in href_lower:
                return "Vendor product information"
            elif 'download' in href_lower:
                return "Product download page"
            elif 'doc' in href_lower or 'manual' in href_lower:
                return "Documentation"
            elif 'support' in href_lower:
                return "Support information"
        
        return None
    
    def _normalize_cpe_component(self, component: str) -> str:
        """Normalize CPE component (handle URL encoding)"""
        if not component or component == '*':
            return component
        
        try:
            # URL decode
            decoded = unquote(component)
            # Replace underscores with spaces for readability
            normalized = decoded.replace('_', ' ')
            return normalized
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
            return None
    
    def _is_relevant_product(self, product: CPEProduct) -> bool:
        """Filter for relevant products"""
        
        # Skip if no meaningful vendor/product info
        if not product.vendor or not product.product:
            return False
        
        if product.vendor == '*' or product.product == '*':
            return False
        
        # Skip deprecated unless configured to include
        if product.deprecated and not getattr(settings, 'CPE_INCLUDE_DEPRECATED', False):
            return False
        
        # Focus on application software primarily
        if product.cpe_name.startswith('cpe:2.3:a:'):
            return True
        
        # Include operating systems
        if product.cpe_name.startswith('cpe:2.3:o:'):
            return True
        
        # Include hardware with software components
        if product.cpe_name.startswith('cpe:2.3:h:') and any(cat in product.categories for cat in ['network', 'security']):
            return True
        
        return False
    
    def _build_search_indices(self):
        """Build search indices for faster lookups"""
        logger.info("Building search indices...")
        
        self._vendor_index = {}
        self._category_index = {}
        self._keyword_index = {}
        
        for product in self.cpe_products:
            # Vendor index
            vendor_key = product.vendor.lower()
            if vendor_key not in self._vendor_index:
                self._vendor_index[vendor_key] = []
            self._vendor_index[vendor_key].append(product)
            
            # Category index
            for category in product.categories:
                if category not in self._category_index:
                    self._category_index[category] = []
                self._category_index[category].append(product)
            
            # Keyword index
            for keyword in product.keywords:
                if len(keyword) > 2:  # Skip very short keywords
                    if keyword not in self._keyword_index:
                        self._keyword_index[keyword] = []
                    self._keyword_index[keyword].append(product)
    
    async def _cache_products(self):
        """Cache processed products to disk"""
        try:
            cache_data = {
                'cached_at': datetime.now().isoformat(),
                'total_products': len(self.cpe_products),
                'products': [product.to_dict() for product in self.cpe_products]
            }
            
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            logger.info(f"Cached {len(self.cpe_products)} products to {self.cache_file}")
            
        except Exception as e:
            logger.error(f"Failed to cache products: {e}")
    
    def load_cached_cpe_data(self) -> bool:
        """Load products from cache"""
        try:
            if not self.cache_file.exists():
                return False
            
            # Check cache age
            file_age = datetime.now() - datetime.fromtimestamp(self.cache_file.stat().st_mtime)
            cache_expiry_hours = getattr(settings, 'CPE_CACHE_EXPIRY_HOURS', 24)
            
            if file_age > timedelta(hours=cache_expiry_hours):
                logger.info("CPE cache is stale")
                return False
            
            with open(self.cache_file, 'r') as f:
                cache_data = json.load(f)
            
            # Reconstruct products
            products = []
            for product_dict in cache_data.get('products', []):
                try:
                    product = CPEProduct.from_dict(product_dict)
                    products.append(product)
                except Exception as e:
                    logger.warning(f"Failed to load cached product: {e}")
            
            self.cpe_products = products
            self._build_search_indices()
            
            logger.info(f"Loaded {len(products)} products from cache")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load cached CPE data: {e}")
            return False
    
    def enhanced_search_products(self, query: str, vendor_filter: Optional[str] = None,
                               product_filter: Optional[str] = None, version_filter: Optional[str] = None,
                               category_filter: Optional[str] = None, include_deprecated: bool = False,
                               limit: int = 50, offset: int = 0) -> Tuple[List[CPEProduct], int]:
        """
        Enhanced search with comprehensive metadata matching
        
        This is the main improvement that fixes Windows 11 and other search issues
        """
        if not self.cpe_products:
            return [], 0
        
        # Preprocess query
        normalized_query = self._preprocess_search_query(query.strip())
        query_tokens = set(re.findall(r'\b\w{2,}\b', normalized_query.lower()))
        
        logger.info(f"Enhanced search: '{query}' -> '{normalized_query}' -> tokens: {query_tokens}")
        
        matching_products = []
        
        # Fast path: check indices first for common queries
        index_matches = self._search_indices(normalized_query, query_tokens)
        
        # If we have index matches, use them as candidates, otherwise search all
        search_candidates = index_matches if index_matches else self.cpe_products
        
        for product in search_candidates:
            # Apply filters
            if product.deprecated and not include_deprecated:
                continue
            
            if vendor_filter and not self._matches_filter(product.vendor, vendor_filter):
                continue
            
            if product_filter and not self._matches_filter(product.product, product_filter):
                continue
            
            if version_filter and not self._matches_filter(product.version, version_filter):
                continue
                
            if category_filter and category_filter not in product.categories:
                continue
            
            # Calculate match score
            match_score = self._calculate_comprehensive_match_score(
                product, normalized_query, query_tokens, query
            )
            
            if match_score > 0:
                product._search_score = match_score
                matching_products.append(product)
        
        # Sort by combined score (match + popularity)
        matching_products.sort(
            key=lambda p: getattr(p, '_search_score', 0) + (p.popularity_score * 0.1),
            reverse=True
        )
        
        total_count = len(matching_products)
        paginated_results = matching_products[offset:offset + limit]
        
        logger.info(f"Enhanced search found {total_count} matches, returning {len(paginated_results)}")
        
        return paginated_results, total_count
    
    def _preprocess_search_query(self, query: str) -> str:
        """Preprocess query for better matching"""
        if not query:
            return ""
        
        query = query.lower().strip()
        
        # Handle common patterns
        query_patterns = [
            # Windows versions
            (r'\bwindows\s+11\b', 'windows 11 microsoft operating system'),
            (r'\bwindows\s+10\b', 'windows 10 microsoft operating system'),
            (r'\bwin\s*11\b', 'windows 11 microsoft'),
            (r'\bwin\s*10\b', 'windows 10 microsoft'),
            (r'\bwindows\s+server\s+(\d{4})', r'windows server \1 microsoft operating system'),
            
            # Database patterns
            (r'\bmysql\s+(\d+\.?\d*)', r'mysql \1 oracle database'),
            (r'\bpostgresql\s+(\d+\.?\d*)', r'postgresql \1 database'),
            (r'\boracle\s+database', 'oracle database management system'),
            
            # Web server patterns
            (r'\bapache\s+(\d+\.?\d*)', r'apache http server \1 web server'),
            (r'\bnginx\s+(\d+\.?\d*)', r'nginx \1 web server'),
            (r'\biis\s+(\d+\.?\d*)', r'internet information services \1 microsoft web server'),
            
            # Framework patterns
            (r'\bspring\s+boot', 'spring boot framework java'),
            (r'\bdjango\s+(\d+\.?\d*)', r'django \1 python framework'),
            
            # General patterns
            (r'\bweb\s+server', 'web server http'),
            (r'\bdatabase\s+server', 'database management system'),
            (r'\bapp\s+server', 'application server'),
        ]
        
        # Apply pattern transformations
        for pattern, replacement in query_patterns:
            query = re.sub(pattern, replacement, query)
        
        return query
    
    def _search_indices(self, query: str, tokens: Set[str]) -> List[CPEProduct]:
        """Search using pre-built indices for common patterns"""
        candidates = set()
        
        # Search vendor index
        for token in tokens:
            if token in self._vendor_index:
                candidates.update(self._vendor_index[token])
        
        # Search keyword index
        for token in tokens:
            if token in self._keyword_index:
                candidates.update(self._keyword_index[token][:100])  # Limit per keyword
        
        # Search category index for category-related tokens
        category_tokens = {'web', 'server', 'database', 'operating', 'system', 'framework'}
        if tokens.intersection(category_tokens):
            for category, products in self._category_index.items():
                category_words = set(category.replace('_', ' ').split())
                if tokens.intersection(category_words):
                    candidates.update(products[:50])  # Limit per category
        
        return list(candidates)
    
    def _calculate_comprehensive_match_score(self, product: CPEProduct, 
                                           normalized_query: str, query_tokens: Set[str], 
                                           original_query: str) -> float:
        """Calculate comprehensive match score using all metadata"""
        
        score = 0.0
        original_tokens = set(re.findall(r'\b\w{2,}\b', original_query.lower()))
        all_tokens = query_tokens.union(original_tokens)
        
        # 1. Core field matches (highest priority)
        if normalized_query in product.vendor.lower():
            score += 60
        if normalized_query in product.product.lower():
            score += 80
        if normalized_query in product.version.lower():
            score += 40
            
        # 2. Token-based matching
        matching_tokens = all_tokens.intersection(product.search_tokens)
        score += len(matching_tokens) * 15
        
        # 3. Title matches (very important for readability)
        for title in product.titles:
            title_lower = title.title.lower()
            if normalized_query in title_lower:
                score += 70
            title_tokens = set(re.findall(r'\b\w{2,}\b', title_lower))
            title_matches = all_tokens.intersection(title_tokens)
            score += len(title_matches) * 10
        
        # 4. Category matches
        for category in product.categories:
            category_readable = category.replace('_', ' ')
            if any(token in category_readable for token in all_tokens):
                score += 50
                
        # 5. Alternative names and vendor aliases
        for alt_name in product.alternative_names:
            if normalized_query in alt_name:
                score += 45
        
        for alias in product.vendor_aliases:
            if any(token in alias.lower() for token in all_tokens):
                score += 35
        
        # 6. Keyword matches
        keyword_matches = all_tokens.intersection(product.keywords)
        score += len(keyword_matches) * 8
        
        # 7. Version-specific bonuses
        if self._is_version_query(original_query):
            version_score = self._calculate_version_match_score(
                original_query, product.version, product
            )
            score += version_score
        
        # 8. Reference content matches
        for ref in product.references:
            if ref.content:
                ref_lower = ref.content.lower()
                if normalized_query in ref_lower:
                    score += 20
                ref_tokens = set(re.findall(r'\b\w{2,}\b', ref_lower))
                ref_matches = all_tokens.intersection(ref_tokens)
                score += len(ref_matches) * 3
        
        # 9. Exact match bonuses
        if original_query.lower() == product.vendor.lower():
            score += 100
        if original_query.lower() == product.product.lower():
            score += 120
        if original_query.lower() in [t.title.lower() for t in product.titles]:
            score += 90
        
        return score
    
    def _is_version_query(self, query: str) -> bool:
        """Check if query contains version patterns"""
        version_patterns = [
            r'\d+',              # Any digit
            r'\d+\.\d+',         # x.y
            r'\d+\.\d+\.\d+',    # x.y.z
            r'\d{4}',            # 2019, 2022
            r'\d+[hH]\d+',       # 21H2
        ]
        return any(re.search(pattern, query) for pattern in version_patterns)
    
    def _calculate_version_match_score(self, query: str, product_version: str, 
                                     product: CPEProduct) -> float:
        """Calculate version-specific match score"""
        if not product_version or product_version == '*':
            return 0
        
        score = 0
        query_lower = query.lower()
        version_lower = product_version.lower()
        
        # Extract version numbers from query
        query_versions = re.findall(r'\d+(?:\.\d+)*', query)
        product_versions = re.findall(r'\d+(?:\.\d+)*', product_version)
        
        for q_ver in query_versions:
            for p_ver in product_versions:
                if q_ver == p_ver:
                    score += 30  # Exact version match
                elif q_ver in p_ver or p_ver in q_ver:
                    score += 20  # Partial version match
        
        # Special handling for Windows versions
        if 'windows' in product.product.lower() or any('windows' in t.title.lower() for t in product.titles):
            if '11' in query and '11' in version_lower:
                score += 40
            elif '10' in query and '10' in version_lower:
                score += 40
            elif 'server' in query and 'server' in version_lower:
                # Extract server version (2019, 2022, etc.)
                server_versions = re.findall(r'20\d{2}', query)
                if server_versions:
                    for sv in server_versions:
                        if sv in product_version:
                            score += 35
        
        return score
    
    def _matches_filter(self, field_value: str, filter_value: str) -> bool:
        """Check if field matches filter"""
        if not field_value or not filter_value:
            return True
        return filter_value.lower() in field_value.lower()
    
    def get_search_suggestions(self, partial_query: str, limit: int = 10) -> List[str]:
        """Get search suggestions based on metadata"""
        if len(partial_query) < 2:
            return []
        
        suggestions = set()
        partial_lower = partial_query.lower()
        
        # Sample products for performance
        sample_size = min(1000, len(self.cpe_products))
        sample_products = self.cpe_products[:sample_size]
        
        for product in sample_products:
            # Vendor suggestions
            if product.vendor.lower().startswith(partial_lower):
                suggestions.add(product.vendor)
            
            # Product suggestions
            if product.product.lower().startswith(partial_lower):
                suggestions.add(f"{product.vendor} {product.product}")
            
            # Title suggestions
            for title in product.titles:
                if title.title.lower().startswith(partial_lower):
                    suggestions.add(title.title)
            
            # Category suggestions
            for category in product.categories:
                readable_category = category.replace('_', ' ')
                if readable_category.startswith(partial_lower):
                    suggestions.add(readable_category)
            
            # Alternative name suggestions
            for alt_name in product.alternative_names:
                if alt_name.startswith(partial_lower):
                    suggestions.add(alt_name)
        
        return sorted(list(suggestions))[:limit]
    
    def get_vendors(self, query: Optional[str] = None, limit: int = 50) -> List[str]:
        """Get list of vendors"""
        vendors = set(product.vendor for product in self.cpe_products if product.vendor)
        
        if query:
            query_lower = query.lower()
            vendors = {v for v in vendors if query_lower in v.lower()}
        
        return sorted(list(vendors))[:limit]
    
    def get_categories(self, limit: int = 50) -> List[str]:
        """Get list of available categories"""
        categories = set()
        for product in self.cpe_products:
            categories.update(product.categories)
        
        # Convert to readable format
        readable_categories = [cat.replace('_', ' ').title() for cat in categories]
        return sorted(readable_categories)[:limit]
    
    def get_product_by_id(self, cpe_name_id: str) -> Optional[CPEProduct]:
        """Get product by CPE name ID"""
        for product in self.cpe_products:
            if product.cpe_name_id == cpe_name_id:
                return product
        return None
    
    def debug_search(self, query: str, limit: int = 5) -> Dict:
        """Debug search functionality"""
        logger.info(f"=== DEBUG SEARCH: '{query}' ===")
        
        if not self.cpe_products:
            return {"error": "No CPE products loaded"}
        
        normalized_query = self._preprocess_search_query(query)
        query_tokens = set(re.findall(r'\b\w{2,}\b', normalized_query.lower()))
        
        debug_results = []
        sample_products = self.cpe_products[:100]  # Debug with sample
        
        for product in sample_products:
            if product.deprecated:
                continue
            
            score = self._calculate_comprehensive_match_score(
                product, normalized_query, query_tokens, query
            )
            
            if score > 0:
                debug_info = {
                    'cpe_name': product.cpe_name,
                    'vendor': product.vendor,
                    'product': product.product,
                    'version': product.version,
                    'score': score,
                    'popularity_score': product.popularity_score,
                    'categories': list(product.categories),
                    'titles': [t.title for t in product.titles],
                    'keywords': list(product.keywords)[:10],  # First 10 keywords
                }
                debug_results.append(debug_info)
        
        debug_results.sort(key=lambda x: x['score'], reverse=True)
        
        return {
            'query': query,
            'normalized_query': normalized_query,
            'query_tokens': list(query_tokens),
            'total_matches': len(debug_results),
            'top_matches': debug_results[:limit],
            'sample_size': len(sample_products)
        }