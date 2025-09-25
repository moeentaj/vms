"""
CPE Natural Language Query Processor
app/services/cpe_nlp_processor.py

Integrates with your existing CPE infrastructure to provide natural language processing
"""

import re
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)

@dataclass
class CPEQuery:
    """Structured CPE query extracted from natural language"""
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    part: Optional[str] = None  # 'a' for application, 'o' for OS, 'h' for hardware
    confidence: float = 0.0
    original_query: str = ""
    extracted_terms: List[str] = None
    
    def __post_init__(self):
        if self.extracted_terms is None:
            self.extracted_terms = []

class CPEQueryProcessor:
    """Process natural language queries into structured CPE searches"""
    
    def __init__(self):
        self.vendor_patterns = self._load_vendor_patterns()
        self.product_patterns = self._load_product_patterns()
        self.version_patterns = self._load_version_patterns()
        self.part_indicators = self._load_part_indicators()
        
    def _load_vendor_patterns(self) -> Dict[str, List[str]]:
        """Load vendor name patterns and aliases"""
        return {
            'apache': ['apache', 'apache software foundation', 'asf'],
            'microsoft': ['microsoft', 'ms', 'msft'],
            'oracle': ['oracle', 'oracle corporation', 'sun microsystems', 'sun'],
            'google': ['google', 'alphabet inc'],
            'amazon': ['amazon', 'aws', 'amazon web services'],
            'nginx': ['nginx', 'nginx inc'],
            'postgresql': ['postgresql', 'postgres', 'postgresql global development group'],
            'mysql': ['mysql', 'oracle mysql'],
            'mongodb': ['mongodb', 'mongodb inc'],
            'elastic': ['elastic', 'elasticsearch'],
            'redis': ['redis', 'redis labs'],
            'docker': ['docker', 'docker inc'],
            'kubernetes': ['kubernetes', 'k8s', 'cncf'],
            'atlassian': ['atlassian', 'atlassian pty ltd'],
            'jetbrains': ['jetbrains', 'jetbrains s.r.o.'],
            'vmware': ['vmware', 'vmware inc'],
            'citrix': ['citrix', 'citrix systems'],
            'ibm': ['ibm', 'international business machines'],
            'redhat': ['red hat', 'redhat', 'red hat inc'],
            'canonical': ['canonical', 'ubuntu'],
            'cisco': ['cisco', 'cisco systems'],
            'mozilla': ['mozilla', 'mozilla foundation'],
            'nodejs': ['nodejs', 'node.js foundation'],
            'python': ['python', 'python software foundation'],
            'php': ['php', 'php group'],
            'ruby': ['ruby', 'ruby core team'],
            'golang': ['go', 'golang', 'google go']
        }
    
    def _load_product_patterns(self) -> Dict[str, List[str]]:
        """Load product name patterns and aliases"""
        return {
            'http_server': ['apache', 'apache http server', 'apache2', 'httpd'],
            'nginx': ['nginx', 'nginx web server'],
            'iis': ['iis', 'internet information server', 'internet information services'],
            'mysql': ['mysql', 'mysql server', 'mysql database'],
            'postgresql': ['postgresql', 'postgres', 'postgres database'],
            'mongodb': ['mongodb', 'mongo database', 'mongo'],
            'redis': ['redis', 'redis server'],
            'elasticsearch': ['elasticsearch', 'elastic search'],
            'windows': ['windows', 'windows server', 'microsoft windows'],
            'linux': ['linux', 'linux kernel'],
            'ubuntu': ['ubuntu', 'ubuntu linux'],
            'centos': ['centos', 'centos linux'],
            'rhel': ['rhel', 'red hat enterprise linux'],
            'docker': ['docker', 'docker engine'],
            'kubernetes': ['kubernetes', 'k8s'],
            'tomcat': ['tomcat', 'apache tomcat'],
            'jenkins': ['jenkins', 'jenkins ci'],
            'wordpress': ['wordpress', 'wp'],
            'drupal': ['drupal', 'drupal cms'],
            'joomla': ['joomla', 'joomla cms'],
            'node.js': ['node.js', 'nodejs', 'node'],
            'python': ['python', 'python interpreter'],
            'java': ['java', 'openjdk', 'oracle java'],
            'php': ['php', 'php interpreter'],
            'ruby': ['ruby', 'ruby interpreter'],
            'go': ['go', 'golang'],
            'chrome': ['chrome', 'google chrome'],
            'firefox': ['firefox', 'mozilla firefox'],
            'safari': ['safari', 'apple safari'],
            'edge': ['edge', 'microsoft edge'],
            'spring': ['spring', 'spring framework'],
            'express': ['express', 'express.js'],
            'flask': ['flask', 'flask framework'],
            'django': ['django', 'django framework'],
            'rails': ['rails', 'ruby on rails']
        }
    
    def _load_version_patterns(self) -> List[str]:
        """Load version detection patterns"""
        return [
            r'\b(\d+)\.(\d+)\.(\d+)\.(\d+)\b',  # 1.2.3.4
            r'\b(\d+)\.(\d+)\.(\d+)-([a-zA-Z0-9]+)\b',  # 1.2.3-beta1
            r'\b(\d+)\.(\d+)\.(\d+)\b',  # 1.2.3
            r'\b(\d+)\.(\d+)\b',  # 1.2
            r'\bv(\d+(?:\.\d+)*)\b',  # v1.2.3
            r'\bversion\s+(\d+(?:\.\d+)*)\b',  # version 1.2.3
            r'\b(\d+(?:\.\d+)*)\s*(?:lts|stable|release)\b'  # 1.2.3 lts
        ]
    
    def _load_part_indicators(self) -> Dict[str, List[str]]:
        """Load indicators for CPE part classification"""
        return {
            'a': [  # Applications
                'server', 'service', 'application', 'app', 'software', 'program',
                'database', 'db', 'web server', 'cms', 'framework', 'library',
                'api', 'daemon', 'engine', 'runtime', 'interpreter',
                'browser', 'client', 'tool', 'utility', 'plugin', 'extension'
            ],
            'o': [  # Operating Systems
                'os', 'operating system', 'linux', 'windows', 'macos', 'unix',
                'distribution', 'distro', 'kernel', 'system'
            ],
            'h': [  # Hardware
                'hardware', 'device', 'router', 'switch', 'firewall', 'appliance',
                'embedded', 'firmware', 'chip', 'processor', 'controller'
            ]
        }
    
    def process_query(self, query: str) -> CPEQuery:
        """Process a natural language query into structured CPE components"""
        query_lower = query.lower().strip()
        
        # Initialize result
        result = CPEQuery(
            original_query=query,
            extracted_terms=[],
            confidence=0.0
        )
        
        # Extract version information
        version_info = self._extract_version(query_lower)
        if version_info:
            result.version = version_info['version']
            result.confidence += 0.3
            result.extracted_terms.append(f"version: {version_info['version']}")
        
        # Extract vendor information
        vendor_info = self._extract_vendor(query_lower)
        if vendor_info:
            result.vendor = vendor_info['vendor']
            result.confidence += 0.3
            result.extracted_terms.append(f"vendor: {vendor_info['vendor']}")
        
        # Extract product information
        product_info = self._extract_product(query_lower, result.vendor)
        if product_info:
            result.product = product_info['product']
            result.confidence += 0.3
            result.extracted_terms.append(f"product: {product_info['product']}")
        
        # Determine CPE part (application, OS, hardware)
        part_info = self._classify_part(query_lower)
        if part_info:
            result.part = part_info['part']
            result.confidence += 0.1
            result.extracted_terms.append(f"type: {part_info['description']}")
        
        # Apply confidence adjustments
        result.confidence = min(result.confidence, 1.0)
        
        return result
    
    def _extract_version(self, query: str) -> Optional[Dict]:
        """Extract version information from query"""
        for pattern in self.version_patterns:
            match = re.search(pattern, query, re.IGNORECASE)
            if match:
                # Handle different pattern types
                if len(match.groups()) == 4 and '.' in match.group(0) and '-' not in match.group(0):  # 1.2.3.4
                    version = '.'.join(match.groups())
                elif len(match.groups()) == 4 and '-' in match.group(0):  # 1.2.3-beta
                    version = f"{match.group(1)}.{match.group(2)}.{match.group(3)}-{match.group(4)}"
                elif len(match.groups()) == 3:  # 1.2.3
                    version = '.'.join(match.groups())
                elif len(match.groups()) == 2:  # 1.2
                    version = '.'.join(match.groups())
                else:  # single capture group
                    version = match.group(1)
                
                return {
                    'version': version,
                    'confidence': 0.9,
                    'match': match.group(0)
                }
        return None
    
    def _extract_vendor(self, query: str) -> Optional[Dict]:
        """Extract vendor information from query"""
        best_match = None
        best_confidence = 0
        
        for vendor, aliases in self.vendor_patterns.items():
            for alias in aliases:
                if alias in query:
                    confidence = len(alias) / len(query)  # Longer matches get higher confidence
                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_match = {
                            'vendor': vendor,
                            'confidence': min(confidence * 2, 1.0),  # Boost confidence
                            'matched_alias': alias
                        }
        
        return best_match
    
    def _extract_product(self, query: str, vendor: Optional[str] = None) -> Optional[Dict]:
        """Extract product information from query"""
        best_match = None
        best_confidence = 0
        
        for product, aliases in self.product_patterns.items():
            for alias in aliases:
                if alias in query:
                    confidence = len(alias) / len(query)
                    
                    # Boost confidence if vendor matches known patterns
                    if vendor and self._vendor_product_match(vendor, product):
                        confidence *= 1.5
                    
                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_match = {
                            'product': product,
                            'confidence': min(confidence * 2, 1.0),
                            'matched_alias': alias
                        }
        
        return best_match
    
    def _vendor_product_match(self, vendor: str, product: str) -> bool:
        """Check if vendor and product are known to match"""
        known_combinations = {
            'apache': ['http_server', 'tomcat'],
            'microsoft': ['iis', 'windows'],
            'oracle': ['mysql', 'java'],
            'postgresql': ['postgresql'],
            'mongodb': ['mongodb'],
            'nginx': ['nginx'],
            'elastic': ['elasticsearch'],
            'redis': ['redis'],
            'google': ['chrome'],
            'mozilla': ['firefox']
        }
        
        return product in known_combinations.get(vendor, [])
    
    def _classify_part(self, query: str) -> Optional[Dict]:
        """Classify the CPE part type (application, OS, hardware)"""
        scores = {'a': 0, 'o': 0, 'h': 0}
        
        for part, indicators in self.part_indicators.items():
            for indicator in indicators:
                if indicator in query:
                    scores[part] += len(indicator) / len(query)
        
        if max(scores.values()) > 0:
            best_part = max(scores, key=scores.get)
            descriptions = {
                'a': 'Application',
                'o': 'Operating System', 
                'h': 'Hardware'
            }
            
            return {
                'part': best_part,
                'confidence': scores[best_part],
                'description': descriptions[best_part]
            }
        
        # Default to application if unclear
        return {
            'part': 'a',
            'confidence': 0.1,
            'description': 'Application (default)'
        }
    
    def generate_cpe_search_params(self, cpe_query: CPEQuery) -> Dict:
        """Generate search parameters for CPE database query"""
        params = {}
        
        if cpe_query.vendor:
            params['vendor_filter'] = cpe_query.vendor
        
        if cpe_query.product:
            params['product_filter'] = cpe_query.product
        
        if cpe_query.version:
            params['version_filter'] = cpe_query.version
        
        # Generate fuzzy search query
        search_terms = []
        if cpe_query.vendor:
            search_terms.append(cpe_query.vendor)
        if cpe_query.product:
            search_terms.append(cpe_query.product)
        if cpe_query.version:
            search_terms.append(cpe_query.version)
        
        params['query'] = ' '.join(search_terms) if search_terms else cpe_query.original_query
        params['limit'] = 20
        params['include_deprecated'] = False
        
        return params
    
    def explain_query(self, cpe_query: CPEQuery) -> str:
        """Generate human-readable explanation of query processing"""
        if cpe_query.confidence < 0.3:
            return f"I couldn't identify specific software components in '{cpe_query.original_query}'. Try being more specific about the software name and version."
        
        explanation = f"I understood your query '{cpe_query.original_query}' as:\n"
        
        for term in cpe_query.extracted_terms:
            explanation += f"• {term}\n"
        
        explanation += f"\nConfidence: {cpe_query.confidence:.1%}"
        
        if cpe_query.confidence < 0.7:
            explanation += "\n\nTip: Include more specific details like version numbers or full product names to improve search accuracy."
        
        return explanation
    
    def generate_suggestions(self, cpe_query: CPEQuery) -> List[str]:
        """Generate search suggestions for improving queries"""
        suggestions = []
        
        if not cpe_query.vendor and cpe_query.confidence < 0.6:
            suggestions.append("Try including the vendor name (e.g., 'Apache HTTP Server' instead of just 'web server')")
        
        if not cpe_query.version and cpe_query.confidence < 0.7:
            suggestions.append("Consider adding a version number (e.g., 'nginx 1.18' instead of just 'nginx')")
        
        if cpe_query.confidence < 0.4:
            suggestions.append("Use more specific product names (e.g., 'MySQL database' instead of just 'database')")
        
        if len(cpe_query.original_query.split()) == 1:
            suggestions.append("Try using multiple words to describe the software")
        
        return suggestions

# Utility function for testing
def test_nlp_processor():
    """Test function for the NLP processor"""
    processor = CPEQueryProcessor()
    
    test_queries = [
        "Apache HTTP Server 2.4.41",
        "nginx web server version 1.18",
        "MySQL database 8.0.25",
        "Windows Server 2019",
        "PostgreSQL 13.3",
        "web server",
        "database",
        "apache"
    ]
    
    results = []
    for query in test_queries:
        result = processor.process_query(query)
        results.append({
            'query': query,
            'result': asdict(result),
            'params': processor.generate_cpe_search_params(result),
            'explanation': processor.explain_query(result),
            'suggestions': processor.generate_suggestions(result)
        })
    
    return results

if __name__ == "__main__":
    results = test_nlp_processor()
    for result in results:
        print(f"\nQuery: {result['query']}")
        print(f"Confidence: {result['result']['confidence']:.1%}")
        print(f"Search params: {result['params']}")
        print(f"Suggestions: {result['suggestions']}")
        print("-" * 50)