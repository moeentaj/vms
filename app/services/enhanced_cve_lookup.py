"""
Enhanced CVE-CPE Correlation Service with CPE Dictionary 2.0 and CPE Match 2.0
app/services/enhanced_cve_correlation.py

Integrates with the new Enhanced CPE Dictionary system for more accurate vulnerability correlation.
"""

import asyncio
import json
import logging
import time
import re
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, text
from collections import defaultdict

from app.core.database import get_db
from app.models.cve import CVE
from app.models.asset import Asset
from app.services.enhanced_cpe_dictionary import EnhancedCPEDictionaryManager, CPEDictionaryProduct, CPEMatch

logger = logging.getLogger(__name__)

@dataclass
class CVECPECorrelation:
    """Enhanced correlation between CVE and CPE"""
    cve_id: str
    cpe_name: str
    cpe_name_id: str
    asset_id: Optional[int]
    asset_name: Optional[str]
    correlation_type: str  # exact, version_range, vendor_product, fuzzy
    confidence_score: float
    match_criteria: Optional[Dict[str, Any]] = None
    version_affected: bool = True
    vulnerability_context: Optional[Dict[str, Any]] = None

@dataclass
class AssetVulnerabilityProfile:
    """Enhanced vulnerability profile for an asset"""
    asset_id: int
    asset_name: str
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    risk_score: float
    cpe_mappings: List[Dict[str, Any]]
    vulnerability_details: List[CVECPECorrelation]
    last_assessment: datetime
    confidence_level: str

class EnhancedCVECorrelationEngine:
    """Enhanced CVE-CPE correlation engine with NIST CPE 2.0 integration"""
    
    def __init__(self, db: Session):
        self.db = db
        self.cpe_manager = EnhancedCPEDictionaryManager(db)
        
        # Correlation configuration
        self.confidence_thresholds = {
            'exact': 0.95,
            'version_range': 0.85,
            'vendor_product': 0.75,
            'fuzzy': 0.60
        }
        
        # Version parsing patterns
        self.version_patterns = [
            r'^(\d+)\.(\d+)\.(\d+)\.(\d+)$',  # 1.2.3.4
            r'^(\d+)\.(\d+)\.(\d+)$',         # 1.2.3
            r'^(\d+)\.(\d+)$',                # 1.2
            r'^(\d+)$',                       # 1
            r'^v?(\d+[\.\d]*)$',              # v1.2.3 or 1.2.3
        ]

    async def initialize_correlation_engine(self) -> bool:
        """Initialize the correlation engine with CPE data"""
        try:
            # Load CPE data if not already loaded
            if not self.cpe_manager.load_cached_data():
                logger.warning("CPE data not available, attempting to load from cache")
                # Try to load from any available cache
                if not await self._attempt_cpe_data_loading():
                    logger.error("Failed to load CPE data for correlation")
                    return False
            
            logger.info(f"Correlation engine initialized with {len(self.cpe_manager.cpe_products)} CPE products")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize correlation engine: {e}")
            return False

    async def _attempt_cpe_data_loading(self) -> bool:
        """Attempt to load CPE data from various sources"""
        try:
            # Try to load cached data
            if self.cpe_manager.load_cached_data():
                return True
            
            # If no cached data, suggest ingestion
            logger.warning("No CPE data found. Run CPE ingestion first.")
            return False
            
        except Exception as e:
            logger.error(f"Failed to load CPE data: {e}")
            return False

    async def correlate_cve_with_assets(self, cve_id: str, confidence_threshold: float = 0.7) -> List[CVECPECorrelation]:
        """Correlate a CVE with potentially affected assets using enhanced CPE matching"""
        try:
            correlations = []
            
            # Get CVE details
            cve = self.db.query(CVE).filter(CVE.cve_id == cve_id).first()
            if not cve:
                logger.warning(f"CVE {cve_id} not found in database")
                return []
            
            # Extract CPE information from CVE
            cve_cpes = self._extract_cpe_from_cve(cve)
            if not cve_cpes:
                logger.info(f"No CPE information found for CVE {cve_id}")
                return []
            
            # Get all assets with CPE information
            assets = self.db.query(Asset).filter(
                or_(
                    Asset.cpe_name.isnot(None),
                    Asset.primary_service.isnot(None)
                )
            ).all()
            
            for asset in assets:
                asset_correlations = await self._correlate_cve_with_single_asset(
                    cve, cve_cpes, asset, confidence_threshold
                )
                correlations.extend(asset_correlations)
            
            # Sort by confidence score
            correlations.sort(key=lambda x: x.confidence_score, reverse=True)
            
            logger.info(f"Found {len(correlations)} correlations for CVE {cve_id}")
            return correlations
            
        except Exception as e:
            logger.error(f"Failed to correlate CVE {cve_id} with assets: {e}")
            return []

    async def _correlate_cve_with_single_asset(
        self, 
        cve: CVE, 
        cve_cpes: List[str], 
        asset: Asset, 
        confidence_threshold: float
    ) -> List[CVECPECorrelation]:
        """Correlate a CVE with a single asset"""
        correlations = []
        
        try:
            # Get asset CPE information
            asset_cpes = self._extract_asset_cpes(asset)
            
            for cve_cpe in cve_cpes:
                for asset_cpe_info in asset_cpes:
                    correlation = await self._match_cpe_entries(
                        cve, cve_cpe, asset, asset_cpe_info
                    )
                    
                    if correlation and correlation.confidence_score >= confidence_threshold:
                        correlations.append(correlation)
            
            return correlations
            
        except Exception as e:
            logger.error(f"Failed to correlate CVE with asset {asset.id}: {e}")
            return []

    def _extract_cpe_from_cve(self, cve: CVE) -> List[str]:
        """Extract CPE entries from CVE data"""
        cpes = []
        
        try:
            # From cpe_entries field
            if cve.cpe_entries:
                if isinstance(cve.cpe_entries, str):
                    cpe_data = json.loads(cve.cpe_entries)
                else:
                    cpe_data = cve.cpe_entries
                
                if isinstance(cpe_data, list):
                    cpes.extend(cpe_data)
                elif isinstance(cpe_data, dict):
                    # Handle different CPE data structures
                    if 'cpe_match' in cpe_data:
                        for match in cpe_data['cpe_match']:
                            if 'cpe23Uri' in match:
                                cpes.append(match['cpe23Uri'])
            
            # From affected_products field
            if cve.affected_products:
                if isinstance(cve.affected_products, str):
                    products_data = json.loads(cve.affected_products)
                else:
                    products_data = cve.affected_products
                
                if isinstance(products_data, list):
                    for product in products_data:
                        if isinstance(product, dict) and 'cpe' in product:
                            cpes.append(product['cpe'])
            
            # Remove duplicates and filter valid CPEs
            unique_cpes = list(set(cpes))
            valid_cpes = [cpe for cpe in unique_cpes if cpe.startswith('cpe:2.3:')]
            
            return valid_cpes
            
        except Exception as e:
            logger.error(f"Failed to extract CPE from CVE {cve.cve_id}: {e}")
            return []

    def _extract_asset_cpes(self, asset: Asset) -> List[Dict[str, Any]]:
        """Extract CPE information from asset"""
        asset_cpes = []
        
        try:
            # Primary CPE from asset
            if asset.cpe_name:
                asset_cpes.append({
                    'cpe_name': asset.cpe_name,
                    'cpe_name_id': asset.cpe_name_id,
                    'type': 'primary',
                    'service_name': asset.primary_service,
                    'vendor': asset.service_vendor,
                    'version': asset.service_version
                })
            
            # Additional services with CPE
            if asset.additional_services:
                try:
                    if isinstance(asset.additional_services, str):
                        services_data = json.loads(asset.additional_services)
                    else:
                        services_data = asset.additional_services
                    
                    if isinstance(services_data, list):
                        for service in services_data:
                            if isinstance(service, dict) and service.get('cpe_name'):
                                asset_cpes.append({
                                    'cpe_name': service.get('cpe_name'),
                                    'cpe_name_id': service.get('cpe_name_id'),
                                    'type': 'additional',
                                    'service_name': service.get('name'),
                                    'vendor': service.get('vendor'),
                                    'version': service.get('version')
                                })
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in additional_services for asset {asset.id}")
            
            # If no direct CPE, create synthetic CPE info from service details
            if not asset_cpes and (asset.primary_service or asset.service_vendor):
                asset_cpes.append({
                    'cpe_name': None,  # Will be matched against CPE database
                    'cpe_name_id': None,
                    'type': 'inferred',
                    'service_name': asset.primary_service,
                    'vendor': asset.service_vendor,
                    'version': asset.service_version
                })
            
            return asset_cpes
            
        except Exception as e:
            logger.error(f"Failed to extract CPE from asset {asset.id}: {e}")
            return []

    async def _match_cpe_entries(
        self, 
        cve: CVE, 
        cve_cpe: str, 
        asset: Asset, 
        asset_cpe_info: Dict[str, Any]
    ) -> Optional[CVECPECorrelation]:
        """Match CVE CPE with asset CPE information"""
        try:
            correlation_type = 'unknown'
            confidence_score = 0.0
            match_criteria = {}
            version_affected = True
            
            # Parse CVE CPE
            cve_cpe_parts = self._parse_cpe_name(cve_cpe)
            if not cve_cpe_parts:
                return None
            
            # Direct CPE match
            if asset_cpe_info.get('cpe_name'):
                correlation = await self._direct_cpe_match(
                    cve, cve_cpe, cve_cpe_parts, asset, asset_cpe_info
                )
                if correlation:
                    return correlation
            
            # Inferred matching using service details
            correlation = await self._inferred_cpe_match(
                cve, cve_cpe, cve_cpe_parts, asset, asset_cpe_info
            )
            if correlation:
                return correlation
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to match CPE entries: {e}")
            return None

    async def _direct_cpe_match(
        self, 
        cve: CVE, 
        cve_cpe: str, 
        cve_cpe_parts: Dict[str, str], 
        asset: Asset, 
        asset_cpe_info: Dict[str, Any]
    ) -> Optional[CVECPECorrelation]:
        """Direct CPE-to-CPE matching"""
        try:
            asset_cpe = asset_cpe_info['cpe_name']
            asset_cpe_parts = self._parse_cpe_name(asset_cpe)
            
            if not asset_cpe_parts:
                return None
            
            # Exact match
            if cve_cpe == asset_cpe:
                return CVECPECorrelation(
                    cve_id=cve.cve_id,
                    cpe_name=asset_cpe,
                    cpe_name_id=asset_cpe_info.get('cpe_name_id', ''),
                    asset_id=asset.id,
                    asset_name=asset.name,
                    correlation_type='exact',
                    confidence_score=0.95,
                    match_criteria={'match_type': 'exact_cpe'},
                    version_affected=True
                )
            
            # Vendor/product match with version range checking
            if (cve_cpe_parts['vendor'] == asset_cpe_parts['vendor'] and 
                cve_cpe_parts['product'] == asset_cpe_parts['product']):
                
                version_match_result = self._check_version_match(
                    cve_cpe_parts['version'], 
                    asset_cpe_parts['version']
                )
                
                if version_match_result['matches']:
                    confidence = 0.85 if version_match_result['exact'] else 0.75
                    
                    return CVECPECorrelation(
                        cve_id=cve.cve_id,
                        cpe_name=asset_cpe,
                        cpe_name_id=asset_cpe_info.get('cpe_name_id', ''),
                        asset_id=asset.id,
                        asset_name=asset.name,
                        correlation_type='version_range' if not version_match_result['exact'] else 'exact',
                        confidence_score=confidence,
                        match_criteria={
                            'match_type': 'vendor_product_version',
                            'version_match': version_match_result
                        },
                        version_affected=version_match_result['affected']
                    )
            
            # Vendor/product match without version (wildcard scenarios)
            if (cve_cpe_parts['vendor'] == asset_cpe_parts['vendor'] and 
                cve_cpe_parts['product'] == asset_cpe_parts['product'] and
                (cve_cpe_parts['version'] == '*' or asset_cpe_parts['version'] == '*')):
                
                return CVECPECorrelation(
                    cve_id=cve.cve_id,
                    cpe_name=asset_cpe,
                    cpe_name_id=asset_cpe_info.get('cpe_name_id', ''),
                    asset_id=asset.id,
                    asset_name=asset.name,
                    correlation_type='vendor_product',
                    confidence_score=0.70,
                    match_criteria={'match_type': 'vendor_product_wildcard'},
                    version_affected=True
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Failed direct CPE match: {e}")
            return None

    async def _inferred_cpe_match(
        self, 
        cve: CVE, 
        cve_cpe: str, 
        cve_cpe_parts: Dict[str, str], 
        asset: Asset, 
        asset_cpe_info: Dict[str, Any]
    ) -> Optional[CVECPECorrelation]:
        """Inferred matching using CPE database lookup"""
        try:
            service_name = asset_cpe_info.get('service_name', '')
            service_vendor = asset_cpe_info.get('vendor', '')
            service_version = asset_cpe_info.get('version', '')
            
            if not service_name and not service_vendor:
                return None
            
            # Search CPE database for matching products
            search_query = f"{service_vendor} {service_name}".strip()
            if not search_query:
                return None
            
            # Use CPE manager to find potential matches
            search_results = self.cpe_manager.enhanced_search(
                query=search_query,
                filters={'include_deprecated': False},
                limit=20
            )
            
            best_match = None
            best_confidence = 0.0
            
            for cpe_product_data in search_results.get('products', []):
                # Check if this CPE product matches the CVE CPE
                product_cpe = cpe_product_data['cpe_name']
                product_cpe_parts = self._parse_cpe_name(product_cpe)
                
                if not product_cpe_parts:
                    continue
                
                # Check vendor/product match
                if (cve_cpe_parts['vendor'] == product_cpe_parts['vendor'] and 
                    cve_cpe_parts['product'] == product_cpe_parts['product']):
                    
                    # Version matching with asset service version
                    if service_version:
                        version_match = self._check_version_match(
                            cve_cpe_parts['version'], 
                            service_version
                        )
                        
                        if version_match['matches']:
                            confidence = 0.80 if version_match['exact'] else 0.65
                            confidence += cpe_product_data.get('search_score', 0) * 0.1
                            
                            if confidence > best_confidence:
                                best_confidence = confidence
                                best_match = CVECPECorrelation(
                                    cve_id=cve.cve_id,
                                    cpe_name=product_cpe,
                                    cpe_name_id=cpe_product_data['cpe_name_id'],
                                    asset_id=asset.id,
                                    asset_name=asset.name,
                                    correlation_type='inferred',
                                    confidence_score=confidence,
                                    match_criteria={
                                        'match_type': 'inferred_from_service',
                                        'search_query': search_query,
                                        'cpe_search_score': cpe_product_data.get('search_score', 0),
                                        'version_match': version_match
                                    },
                                    version_affected=version_match['affected']
                                )
                    else:
                        # No version info, assume potentially affected
                        confidence = 0.60 + cpe_product_data.get('search_score', 0) * 0.1
                        
                        if confidence > best_confidence:
                            best_confidence = confidence
                            best_match = CVECPECorrelation(
                                cve_id=cve.cve_id,
                                cpe_name=product_cpe,
                                cpe_name_id=cpe_product_data['cpe_name_id'],
                                asset_id=asset.id,
                                asset_name=asset.name,
                                correlation_type='fuzzy',
                                confidence_score=confidence,
                                match_criteria={
                                    'match_type': 'fuzzy_service_match',
                                    'search_query': search_query,
                                    'cpe_search_score': cpe_product_data.get('search_score', 0)
                                },
                                version_affected=True
                            )
            
            return best_match if best_confidence >= self.confidence_thresholds['fuzzy'] else None
            
        except Exception as e:
            logger.error(f"Failed inferred CPE match: {e}")
            return None

    def _parse_cpe_name(self, cpe_name: str) -> Optional[Dict[str, str]]:
        """Parse CPE 2.3 name into components"""
        try:
            parts = cpe_name.split(':')
            if len(parts) < 13 or not cpe_name.startswith('cpe:2.3:'):
                return None
            
            return {
                'part': parts[2],
                'vendor': parts[3],
                'product': parts[4],
                'version': parts[5],
                'update': parts[6],
                'edition': parts[7],
                'language': parts[8],
                'sw_edition': parts[9],
                'target_sw': parts[10],
                'target_hw': parts[11],
                'other': parts[12]
            }
            
        except Exception as e:
            logger.error(f"Failed to parse CPE name {cpe_name}: {e}")
            return None

    def _check_version_match(self, cve_version: str, asset_version: str) -> Dict[str, Any]:
        """Check if asset version is affected by CVE version constraint"""
        try:
            # Handle wildcard cases
            if cve_version == '*' or asset_version == '*':
                return {
                    'matches': True,
                    'exact': False,
                    'affected': True,
                    'reason': 'wildcard'
                }
            
            # Exact version match
            if cve_version == asset_version:
                return {
                    'matches': True,
                    'exact': True,
                    'affected': True,
                    'reason': 'exact_match'
                }
            
            # Parse and compare versions
            cve_version_parsed = self._parse_version(cve_version)
            asset_version_parsed = self._parse_version(asset_version)
            
            if cve_version_parsed and asset_version_parsed:
                comparison = self._compare_versions(asset_version_parsed, cve_version_parsed)
                
                # For CVE correlation, we generally assume the asset is affected
                # if the version is less than or equal to the CVE version
                # This logic can be enhanced with CVE-specific version range data
                affected = comparison <= 0
                
                return {
                    'matches': True,
                    'exact': comparison == 0,
                    'affected': affected,
                    'reason': f'version_comparison_{comparison}',
                    'cve_version_parsed': cve_version_parsed,
                    'asset_version_parsed': asset_version_parsed
                }
            
            # Fallback: string comparison
            matches = cve_version.lower() in asset_version.lower() or asset_version.lower() in cve_version.lower()
            
            return {
                'matches': matches,
                'exact': False,
                'affected': matches,
                'reason': 'string_comparison'
            }
            
        except Exception as e:
            logger.error(f"Failed to check version match: {e}")
            return {
                'matches': False,
                'exact': False,
                'affected': False,
                'reason': f'error: {str(e)}'
            }

    def _parse_version(self, version: str) -> Optional[List[int]]:
        """Parse version string into comparable components"""
        try:
            # Remove common prefixes
            version = re.sub(r'^v\.?', '', version, flags=re.IGNORECASE)
            
            # Try different version patterns
            for pattern in self.version_patterns:
                match = re.match(pattern, version)
                if match:
                    # Convert matched groups to integers
                    parts = []
                    for group in match.groups():
                        try:
                            parts.append(int(group))
                        except ValueError:
                            continue
                    return parts if parts else None
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to parse version {version}: {e}")
            return None

    def _compare_versions(self, version1: List[int], version2: List[int]) -> int:
        """Compare two parsed version lists (-1, 0, 1)"""
        try:
            # Pad shorter version with zeros
            max_len = max(len(version1), len(version2))
            v1 = version1 + [0] * (max_len - len(version1))
            v2 = version2 + [0] * (max_len - len(version2))
            
            # Compare component by component
            for i in range(max_len):
                if v1[i] < v2[i]:
                    return -1
                elif v1[i] > v2[i]:
                    return 1
            
            return 0
            
        except Exception as e:
            logger.error(f"Failed to compare versions: {e}")
            return 0

    async def assess_asset_vulnerabilities(self, asset_id: int, confidence_threshold: float = 0.7) -> Optional[AssetVulnerabilityProfile]:
        """Comprehensive vulnerability assessment for a single asset"""
        try:
            # Get asset details
            asset = self.db.query(Asset).filter(Asset.id == asset_id).first()
            if not asset:
                return None
            
            # Get all CVEs (or recent CVEs for performance)
            recent_date = datetime.now() - timedelta(days=365 * 2)  # Last 2 years
            cves = self.db.query(CVE).filter(
                or_(
                    CVE.published_date >= recent_date,
                    CVE.cvss_score >= 7.0  # Always include high/critical
                )
            ).all()
            
            vulnerability_details = []
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            # Check each CVE against this asset
            for cve in cves:
                correlations = await self._correlate_cve_with_single_asset(
                    cve, 
                    self._extract_cpe_from_cve(cve), 
                    asset, 
                    confidence_threshold
                )
                
                if correlations:
                    # Take the highest confidence correlation
                    best_correlation = max(correlations, key=lambda x: x.confidence_score)
                    vulnerability_details.append(best_correlation)
                    
                    # Count by severity
                    severity = cve.severity or 'unknown'
                    if severity.lower() in ['critical', 'high', 'medium', 'low']:
                        severity_counts[severity.lower()] += 1
            
            # Calculate risk score
            risk_score = self._calculate_asset_risk_score(vulnerability_details, asset)
            
            # Determine confidence level
            avg_confidence = sum(v.confidence_score for v in vulnerability_details) / len(vulnerability_details) if vulnerability_details else 0
            confidence_level = 'high' if avg_confidence >= 0.8 else 'medium' if avg_confidence >= 0.6 else 'low'
            
            # Get CPE mappings
            cpe_mappings = self._extract_asset_cpes(asset)
            
            return AssetVulnerabilityProfile(
                asset_id=asset.id,
                asset_name=asset.name,
                total_vulnerabilities=len(vulnerability_details),
                critical_vulnerabilities=severity_counts['critical'],
                high_vulnerabilities=severity_counts['high'],
                medium_vulnerabilities=severity_counts['medium'],
                low_vulnerabilities=severity_counts['low'],
                risk_score=risk_score,
                cpe_mappings=cpe_mappings,
                vulnerability_details=vulnerability_details,
                last_assessment=datetime.now(),
                confidence_level=confidence_level
            )
            
        except Exception as e:
            logger.error(f"Failed to assess asset {asset_id} vulnerabilities: {e}")
            return None

    def _calculate_asset_risk_score(self, vulnerabilities: List[CVECPECorrelation], asset: Asset) -> float:
        """Calculate risk score for an asset based on vulnerabilities"""
        try:
            if not vulnerabilities:
                return 0.0
            
            base_score = 0.0
            
            # Get CVE details and calculate weighted score
            for vuln in vulnerabilities:
                cve = self.db.query(CVE).filter(CVE.cve_id == vuln.cve_id).first()
                if cve:
                    cvss_score = cve.cvss_score or 0.0
                    confidence_weight = vuln.confidence_score
                    
                    # Weight by confidence and CVSS score
                    weighted_score = cvss_score * confidence_weight
                    base_score += weighted_score
            
            # Normalize by number of vulnerabilities and apply asset context
            normalized_score = base_score / len(vulnerabilities)
            
            # Asset criticality multiplier
            criticality_multipliers = {
                'critical': 1.5,
                'high': 1.2,
                'medium': 1.0,
                'low': 0.8
            }
            
            criticality_multiplier = criticality_multipliers.get(asset.criticality, 1.0)
            final_score = normalized_score * criticality_multiplier
            
            # Cap at 10.0
            return min(10.0, final_score)
            
        except Exception as e:
            logger.error(f"Failed to calculate risk score: {e}")
            return 0.0

    async def bulk_assess_assets(self, asset_ids: List[int] = None, confidence_threshold: float = 0.7) -> List[AssetVulnerabilityProfile]:
        """Bulk vulnerability assessment for multiple assets"""
        try:
            if asset_ids:
                assets_query = self.db.query(Asset).filter(Asset.id.in_(asset_ids))
            else:
                # Assess all assets with CPE information
                assets_query = self.db.query(Asset).filter(
                    or_(
                        Asset.cpe_name.isnot(None),
                        Asset.primary_service.isnot(None)
                    )
                )
            
            assets = assets_query.all()
            profiles = []
            
            logger.info(f"Starting bulk assessment for {len(assets)} assets")
            
            for i, asset in enumerate(assets):
                logger.info(f"Assessing asset {i+1}/{len(assets)}: {asset.name}")
                
                profile = await self.assess_asset_vulnerabilities(asset.id, confidence_threshold)
                if profile:
                    profiles.append(profile)
            
            logger.info(f"Completed bulk assessment: {len(profiles)} profiles generated")
            return profiles
            
        except Exception as e:
            logger.error(f"Failed bulk asset assessment: {e}")
            return []

    async def get_cve_affected_assets(self, cve_id: str, confidence_threshold: float = 0.7) -> Dict[str, Any]:
        """Get assets potentially affected by a specific CVE"""
        try:
            correlations = await self.correlate_cve_with_assets(cve_id, confidence_threshold)
            
            if not correlations:
                return {
                    'cve_id': cve_id,
                    'affected_assets': [],
                    'total_affected': 0,
                    'confidence_distribution': {},
                    'correlation_types': {}
                }
            
            # Group by asset
            asset_correlations = defaultdict(list)
            for correlation in correlations:
                if correlation.asset_id:
                    asset_correlations[correlation.asset_id].append(correlation)
            
            # Build response
            affected_assets = []
            confidence_distribution = defaultdict(int)
            correlation_types = defaultdict(int)
            
            for asset_id, asset_corr_list in asset_correlations.items():
                # Get best correlation for this asset
                best_correlation = max(asset_corr_list, key=lambda x: x.confidence_score)
                
                affected_assets.append({
                    'asset_id': asset_id,
                    'asset_name': best_correlation.asset_name,
                    'correlation_type': best_correlation.correlation_type,
                    'confidence_score': best_correlation.confidence_score,
                    'cpe_name': best_correlation.cpe_name,
                    'version_affected': best_correlation.version_affected,
                    'match_criteria': best_correlation.match_criteria
                })
                
                # Statistics
                confidence_bucket = 'high' if best_correlation.confidence_score >= 0.8 else 'medium' if best_correlation.confidence_score >= 0.6 else 'low'
                confidence_distribution[confidence_bucket] += 1
                correlation_types[best_correlation.correlation_type] += 1
            
            # Sort by confidence score
            affected_assets.sort(key=lambda x: x['confidence_score'], reverse=True)
            
            return {
                'cve_id': cve_id,
                'affected_assets': affected_assets,
                'total_affected': len(affected_assets),
                'confidence_distribution': dict(confidence_distribution),
                'correlation_types': dict(correlation_types)
            }
            
        except Exception as e:
            logger.error(f"Failed to get affected assets for CVE {cve_id}: {e}")
            return {
                'cve_id': cve_id,
                'affected_assets': [],
                'total_affected': 0,
                'error': str(e)
            }

    async def search_vulnerabilities(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Search vulnerabilities with various filters"""
        try:
            # Build base query
            query = self.db.query(CVE)
            
            # Apply filters
            if filters.get('severity'):
                severities = [s.strip().lower() for s in filters['severity'].split(',')]
                query = query.filter(func.lower(CVE.severity).in_(severities))
            
            if filters.get('cvss_min'):
                query = query.filter(CVE.cvss_score >= float(filters['cvss_min']))
            
            if filters.get('cvss_max'):
                query = query.filter(CVE.cvss_score <= float(filters['cvss_max']))
            
            if filters.get('published_after'):
                published_after = datetime.fromisoformat(filters['published_after'].replace('Z', '+00:00'))
                query = query.filter(CVE.published_date >= published_after)
            
            if filters.get('published_before'):
                published_before = datetime.fromisoformat(filters['published_before'].replace('Z', '+00:00'))
                query = query.filter(CVE.published_date <= published_before)
            
            if filters.get('cpe_vendor'):
                # Search in cpe_entries JSON field
                query = query.filter(CVE.cpe_entries.contains(filters['cpe_vendor']))
            
            if filters.get('cpe_product'):
                query = query.filter(CVE.cpe_entries.contains(filters['cpe_product']))
            
            # Pagination
            limit = min(int(filters.get('limit', 50)), 200)
            offset = int(filters.get('offset', 0))
            
            total_count = query.count()
            cves = query.offset(offset).limit(limit).all()
            
            # Format results
            results = []
            for cve in cves:
                cve_data = {
                    'cve_id': cve.cve_id,
                    'description': cve.description,
                    'cvss_score': cve.cvss_score,
                    'severity': cve.severity,
                    'published_date': cve.published_date.isoformat() if cve.published_date else None,
                    'cpe_entries': cve.cpe_entries
                }
                
                # Add correlation info if requested
                if filters.get('include_asset_correlation'):
                    correlation_summary = await self.get_cve_affected_assets(
                        cve.cve_id, 
                        float(filters.get('correlation_confidence', 0.7))
                    )
                    cve_data['asset_correlation'] = {
                        'total_affected': correlation_summary['total_affected'],
                        'correlation_types': correlation_summary['correlation_types']
                    }
                
                results.append(cve_data)
            
            return {
                'vulnerabilities': results,
                'total_count': total_count,
                'limit': limit,
                'offset': offset,
                'filters_applied': filters
            }
            
        except Exception as e:
            logger.error(f"Failed to search vulnerabilities: {e}")
            return {
                'vulnerabilities': [],
                'total_count': 0,
                'error': str(e)
            }