"""
Enhanced CPE Models - app/models/cpe.py
Complete replacement for your CPE data models with rich metadata support.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from datetime import datetime
import re
import json
import logging

logger = logging.getLogger(__name__)

@dataclass
class CPETitle:
    """Enhanced title with language and context information"""
    title: str
    lang: str = 'en'
    context: Optional[str] = None

@dataclass
class CPEReference:
    """Enhanced reference with type and content"""
    href: str
    ref_type: Optional[str] = None
    content: Optional[str] = None

@dataclass
class CPEProduct:
    """Enhanced CPE product with comprehensive metadata for search"""
    
    # Core CPE 2.3 components
    cpe_name: str
    cpe_name_id: str
    vendor: str
    product: str
    version: str
    update: str = '*'
    edition: str = '*'
    language: str = '*'
    sw_edition: str = '*'
    target_sw: str = '*'
    target_hw: str = '*'
    other: str = '*'
    
    # Enhanced metadata
    titles: List[CPETitle] = field(default_factory=list)
    references: List[CPEReference] = field(default_factory=list)
    
    # Lifecycle information
    deprecated: bool = False
    deprecation_date: Optional[datetime] = None
    deprecated_by: List[str] = field(default_factory=list)
    
    # Timestamps
    last_modified: Optional[datetime] = None
    created: Optional[datetime] = None
    
    # Computed search metadata
    keywords: Set[str] = field(default_factory=set)
    alternative_names: Set[str] = field(default_factory=set)
    vendor_aliases: Set[str] = field(default_factory=set)
    categories: Set[str] = field(default_factory=set)
    searchable_text: str = ""
    search_tokens: Set[str] = field(default_factory=set)
    popularity_score: float = 0.0
    
    def __post_init__(self):
        """Initialize computed fields after creation"""
        self._extract_searchable_metadata()
        self._build_searchable_text()
        self._compute_popularity_score()
    
    def _extract_searchable_metadata(self):
        """Extract keywords, categories, and alternatives from metadata"""
        
        # Process titles for keywords and alternative names
        for title_obj in self.titles:
            title_text = title_obj.title.lower()
            
            # Extract individual words as keywords
            words = re.findall(r'\b\w{3,}\b', title_text)  # 3+ character words
            self.keywords.update(words)
            
            # Look for alternative names in parentheses: "Product Name (Alt Name)"
            alt_patterns = [
                r'\(([^)]+)\)',      # (Alternative)
                r'\[([^\]]+)\]',     # [Alternative]
                r'"([^"]+)"',        # "Alternative"
                r'aka\s+([^,\n]+)',  # aka Alternative
            ]
            
            for pattern in alt_patterns:
                matches = re.findall(pattern, title_text, re.IGNORECASE)
                for match in matches:
                    clean_alt = match.strip().lower()
                    if clean_alt and len(clean_alt) > 2:
                        self.alternative_names.add(clean_alt)
            
            # Extract categories from title text
            self._categorize_from_text(title_text)
        
        # Process references for additional context
        for ref in self.references:
            if ref.content:
                content_lower = ref.content.lower()
                words = re.findall(r'\b\w{3,}\b', content_lower)
                self.keywords.update(words)
                self._categorize_from_text(content_lower)
        
        # Extract vendor aliases
        self._extract_vendor_aliases()
        
        # Clean up keywords (remove common words)
        stop_words = {'the', 'and', 'for', 'with', 'are', 'was', 'this', 'that', 'from', 'can', 'all', 'but', 'not', 'one', 'you', 'use', 'get', 'may', 'has', 'had'}
        self.keywords = {k for k in self.keywords if k not in stop_words and len(k) > 2}
    
    def _categorize_from_text(self, text: str):
        """Extract product categories from text content"""
        
        # Category detection patterns
        category_patterns = {
            'operating_system': [
                'windows', 'linux', 'ubuntu', 'centos', 'debian', 'macos', 'ios', 
                'android', 'operating system', 'os', 'unix', 'solaris', 'aix'
            ],
            'web_server': [
                'web server', 'http server', 'apache', 'nginx', 'iis', 'lighttpd',
                'caddy', 'tomcat', 'jetty'
            ],
            'database': [
                'database', 'mysql', 'postgresql', 'oracle', 'mongodb', 'redis',
                'sqlite', 'mariadb', 'sql server', 'db2', 'cassandra', 'elasticsearch'
            ],
            'application_server': [
                'application server', 'app server', 'jboss', 'websphere', 'weblogic',
                'wildfly', 'glassfish'
            ],
            'framework': [
                'framework', 'django', 'rails', 'spring', 'laravel', 'express',
                'flask', 'symfony', 'react', 'angular', 'vue'
            ],
            'cms': [
                'cms', 'content management', 'wordpress', 'drupal', 'joomla',
                'typo3', 'magento', 'shopify'
            ],
            'virtualization': [
                'vmware', 'docker', 'kubernetes', 'xen', 'virtualbox', 'hyper-v',
                'kvm', 'container', 'virtualization'
            ],
            'security': [
                'firewall', 'antivirus', 'security', 'scanner', 'intrusion',
                'vpn', 'ssl', 'tls', 'encryption'
            ],
            'network': [
                'router', 'switch', 'load balancer', 'proxy', 'gateway',
                'firewall', 'dns', 'dhcp'
            ],
            'development': [
                'ide', 'compiler', 'sdk', 'development', 'visual studio',
                'eclipse', 'intellij', 'git'
            ],
            'browser': [
                'browser', 'chrome', 'firefox', 'safari', 'edge', 'internet explorer'
            ]
        }
        
        for category, keywords in category_patterns.items():
            if any(keyword in text for keyword in keywords):
                self.categories.add(category)
    
    def _extract_vendor_aliases(self):
        """Extract known vendor aliases for better matching"""
        
        vendor_alias_map = {
            'microsoft': ['ms', 'redmond', 'microsoft corporation'],
            'oracle': ['oracle corporation', 'sun microsystems', 'sun'],
            'google': ['alphabet', 'google llc', 'google inc'],
            'apache': ['apache software foundation', 'asf'],
            'redhat': ['red hat', 'ibm', 'red hat inc'],
            'canonical': ['ubuntu'],
            'docker': ['docker inc'],
            'mozilla': ['mozilla foundation', 'mozilla corp'],
            'cisco': ['cisco systems'],
            'ibm': ['international business machines'],
            'hp': ['hewlett packard', 'hewlett-packard'],
            'dell': ['dell technologies', 'dell inc'],
            'vmware': ['vmware inc'],
            'adobe': ['adobe systems'],
            'salesforce': ['salesforce.com'],
            'amazon': ['aws', 'amazon web services'],
        }
        
        vendor_lower = self.vendor.lower()
        for canonical, aliases in vendor_alias_map.items():
            if vendor_lower == canonical or vendor_lower in [a.lower() for a in aliases]:
                self.vendor_aliases.update([canonical] + aliases)
                break
    
    def _build_searchable_text(self):
        """Build comprehensive searchable text from all metadata"""
        
        components = [
            self.vendor,
            self.product,
            self.version if self.version != '*' else '',
            self.cpe_name,
        ]
        
        # Add title text
        for title in self.titles:
            components.append(title.title)
        
        # Add keywords, alternatives, and categories
        components.extend(self.keywords)
        components.extend(self.alternative_names)
        components.extend(self.vendor_aliases)
        components.extend(self.categories)
        
        # Add reference content
        for ref in self.references:
            if ref.content:
                components.append(ref.content)
        
        # Clean and combine
        clean_components = [c.strip() for c in components if c and c.strip()]
        self.searchable_text = ' '.join(clean_components).lower()
        
        # Build search tokens
        self.search_tokens = set(re.findall(r'\b\w{2,}\b', self.searchable_text))
    
    def _compute_popularity_score(self):
        """Compute popularity/relevance score for ranking"""
        
        score = 0.0
        
        # Base score for non-deprecated
        if not self.deprecated:
            score += 10.0
        
        # Recency bonus
        if self.last_modified:
            days_old = (datetime.now() - self.last_modified).days
            if days_old < 30:
                score += 8.0
            elif days_old < 90:
                score += 6.0
            elif days_old < 365:
                score += 4.0
            elif days_old < 730:
                score += 2.0
        
        # Metadata richness bonus
        score += len(self.titles) * 1.0
        score += len(self.references) * 0.5
        score += min(len(self.keywords), 20) * 0.2  # Cap keyword bonus
        
        # Major vendor bonus
        major_vendors = {
            'microsoft', 'oracle', 'google', 'apache', 'cisco', 'ibm', 
            'redhat', 'canonical', 'mozilla', 'adobe', 'vmware'
        }
        if self.vendor.lower() in major_vendors:
            score += 5.0
        
        # Category importance bonus
        important_categories = {'operating_system', 'web_server', 'database', 'browser'}
        score += len(self.categories.intersection(important_categories)) * 3.0
        
        # Version specificity bonus (specific versions rank higher)
        if self.version and self.version != '*' and re.match(r'\d+', self.version):
            score += 2.0
        
        self.popularity_score = score
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'cpe_name': self.cpe_name,
            'cpe_name_id': self.cpe_name_id,
            'vendor': self.vendor,
            'product': self.product,
            'version': self.version,
            'update': self.update,
            'edition': self.edition,
            'language': self.language,
            'sw_edition': self.sw_edition,
            'target_sw': self.target_sw,
            'target_hw': self.target_hw,
            'other': self.other,
            'titles': [{'title': t.title, 'lang': t.lang, 'context': t.context} for t in self.titles],
            'references': [{'href': r.href, 'ref_type': r.ref_type, 'content': r.content} for r in self.references],
            'deprecated': self.deprecated,
            'deprecation_date': self.deprecation_date.isoformat() if self.deprecation_date else None,
            'deprecated_by': self.deprecated_by,
            'last_modified': self.last_modified.isoformat() if self.last_modified else None,
            'created': self.created.isoformat() if self.created else None,
            'keywords': list(self.keywords),
            'alternative_names': list(self.alternative_names),
            'vendor_aliases': list(self.vendor_aliases),
            'categories': list(self.categories),
            'popularity_score': self.popularity_score,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'CPEProduct':
        """Create CPEProduct from dictionary"""
        
        # Parse timestamps
        last_modified = None
        if data.get('last_modified'):
            try:
                last_modified = datetime.fromisoformat(data['last_modified'])
            except:
                pass
        
        created = None
        if data.get('created'):
            try:
                created = datetime.fromisoformat(data['created'])
            except:
                pass
        
        deprecation_date = None
        if data.get('deprecation_date'):
            try:
                deprecation_date = datetime.fromisoformat(data['deprecation_date'])
            except:
                pass
        
        # Parse titles
        titles = []
        for title_data in data.get('titles', []):
            if isinstance(title_data, dict):
                titles.append(CPETitle(
                    title=title_data.get('title', ''),
                    lang=title_data.get('lang', 'en'),
                    context=title_data.get('context')
                ))
        
        # Parse references
        references = []
        for ref_data in data.get('references', []):
            if isinstance(ref_data, dict):
                references.append(CPEReference(
                    href=ref_data.get('href', ''),
                    ref_type=ref_data.get('ref_type'),
                    content=ref_data.get('content')
                ))
        
        return cls(
            cpe_name=data.get('cpe_name', ''),
            cpe_name_id=data.get('cpe_name_id', ''),
            vendor=data.get('vendor', ''),
            product=data.get('product', ''),
            version=data.get('version', '*'),
            update=data.get('update', '*'),
            edition=data.get('edition', '*'),
            language=data.get('language', '*'),
            sw_edition=data.get('sw_edition', '*'),
            target_sw=data.get('target_sw', '*'),
            target_hw=data.get('target_hw', '*'),
            other=data.get('other', '*'),
            titles=titles,
            references=references,
            deprecated=data.get('deprecated', False),
            deprecation_date=deprecation_date,
            deprecated_by=data.get('deprecated_by', []),
            last_modified=last_modified,
            created=created,
            keywords=set(data.get('keywords', [])),
            alternative_names=set(data.get('alternative_names', [])),
            vendor_aliases=set(data.get('vendor_aliases', [])),
            categories=set(data.get('categories', [])),
        )