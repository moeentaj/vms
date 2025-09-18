"""
Enhanced CPE to CVE Correlation Engine
Builds upon your existing system to provide comprehensive CPE to CVE mapping
app/services/cpe_cve_correlation.py
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, text
import re
from collections import defaultdict

from app.core.database import get_db
from app.models.cve import CVE
from app.models.asset import Asset
from app.services.nist_cpe_engine import CPEDatabaseManager, CPEProduct

logger = logging.getLogger(__name__)

@dataclass
class CPECVEMatch:
    """Represents a match between a CPE and CVE"""
    cpe_name: str
    cpe_name_id: str
    cve_id: str
    match_type: str  # exact, partial, version_range, vendor_product
    confidence_score: float
    version_affected: Optional[str] = None
    version_range_start: Optional[str] = None
    version_range_end: Optional[str] = None
    match_details: Optional[Dict] = None

@dataclass
class AssetVulnerabilityAssessment:
    """Vulnerability assessment for a specific asset"""
    asset_id: int
    asset_name: str
    total_cves: int
    critical_cves: int
    high_cves: int
    medium_cves: int
    low_cves: int
    risk_score: float
    affected_services: List[Dict]
    recommendations: List[str]

class CPECVECorrelationEngine:
    """Enhanced correlation engine building on your existing architecture"""
    
    def __init__(self, db: Session):
        self.db = db
        self.cpe_manager = CPEDatabaseManager(db)
        self.version_patterns = [
            r'^(\d+)\.(\d+)\.(\d+)\.(\d+)$',  # 1.2.3.4
            r'^(\d+)\.(\d+)\.(\d+)$',         # 1.2.3
            r'^(\d+)\.(\d+)$',                # 1.2
            r'^(\d+)$',                       # 1
        ]
    
    async def correlate_cpe_to_cves(self, cpe_name: str, include_version_range: bool = True) -> List[CPECVEMatch]:
        """
        Find CVEs that affect a specific CPE
        Enhanced version of your existing correlation logic
        """
        matches = []
        
        # Parse CPE components
        cpe_parts = self.parse_cpe_name(cpe_name)
        if not cpe_parts:
            return matches
        
        # Query CVEs that might affect this CPE
        potential_cves = await self._find_potential_cves(cpe_parts)
        
        for cve in potential_cves:
            cve_matches = await self._match_cpe_to_cve(cpe_name, cpe_parts, cve, include_version_range)
            matches.extend(cve_matches)
        
        # Sort by confidence score
        matches.sort(key=lambda x: x.confidence_score, reverse=True)
        return matches
    
    async def assess_asset_vulnerabilities(self, asset_id: int) -> AssetVulnerabilityAssessment:
        """
        Comprehensive vulnerability assessment for an asset
        Uses your existing Asset model with CPE references
        """
        asset = self.db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset {asset_id} not found")
        
        # Get all CPE references for this asset
        cpe_references = asset.get_all_cpe_references()
        
        all_matches = []
        affected_services = []
        
        # Correlate each CPE reference
        for cpe_ref in cpe_references:
            if cpe_ref['cpe_name']:
                matches = await self.correlate_cpe_to_cves(cpe_ref['cpe_name'])
                all_matches.extend(matches)
                
                if matches:
                    affected_services.append({
                        'service_type': cpe_ref['type'],
                        'service_name': cpe_ref['product'],
                        'vendor': cpe_ref.get('vendor'),
                        'cve_count': len(matches),
                        'highest_cvss': max((self._get_cve_cvss(m.cve_id) or 0 for m in matches), default=0)
                    })
        
        # Remove duplicate CVEs
        unique_cves = {}
        for match in all_matches:
            if match.cve_id not in unique_cves or match.confidence_score > unique_cves[match.cve_id].confidence_score:
                unique_cves[match.cve_id] = match
        
        # Calculate severity counts
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        total_risk_score = 0
        
        for match in unique_cves.values():
            cve = self.db.query(CVE).filter(CVE.cve_id == match.cve_id).first()
            if cve:
                severity = (cve.severity or 'unknown').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                
                # Calculate risk contribution
                cvss_score = cve.get_primary_cvss_score() or 0
                confidence_weight = match.confidence_score
                total_risk_score += cvss_score * confidence_weight
        
        # Generate recommendations
        recommendations = self._generate_recommendations(asset, unique_cves.values(), affected_services)
        
        return AssetVulnerabilityAssessment(
            asset_id=asset.id,
            asset_name=asset.name,
            total_cves=len(unique_cves),
            critical_cves=severity_counts['critical'],
            high_cves=severity_counts['high'],
            medium_cves=severity_counts['medium'],
            low_cves=severity_counts['low'],
            risk_score=total_risk_score,
            affected_services=affected_services,
            recommendations=recommendations
        )
    
    async def bulk_correlate_assets(self, asset_ids: Optional[List[int]] = None) -> Dict[str, any]:
        """
        Bulk correlation for multiple assets
        Enhances your existing correlation functionality
        """
        stats = {
            'assets_processed': 0,
            'total_correlations': 0,
            'high_risk_assets': 0,
            'processing_errors': [],
            'completion_time': None
        }
        
        start_time = time.time()
        
        # Get assets to process
        query = self.db.query(Asset)
        if asset_ids:
            query = query.filter(Asset.id.in_(asset_ids))
        else:
            # Process assets with CPE references
            query = query.filter(
                or_(
                    Asset.cpe_name.isnot(None),
                    Asset.os_cpe_name.isnot(None),
                    Asset.additional_services.isnot(None)
                )
            )
        
        assets = query.all()
        
        for asset in assets:
            try:
                assessment = await self.assess_asset_vulnerabilities(asset.id)
                
                # Update asset with correlation results
                asset.vulnerability_score = assessment.risk_score
                asset.correlation_confidence = self._calculate_overall_confidence(assessment)
                asset.last_vulnerability_scan = datetime.now()
                
                stats['assets_processed'] += 1
                stats['total_correlations'] += assessment.total_cves
                
                if assessment.risk_score > 70 or assessment.critical_cves > 0:
                    stats['high_risk_assets'] += 1
                
            except Exception as e:
                logger.error(f"Error processing asset {asset.id}: {e}")
                stats['processing_errors'].append({
                    'asset_id': asset.id,
                    'error': str(e)
                })
        
        self.db.commit()
        
        stats['completion_time'] = time.time() - start_time
        return stats
    
    def parse_cpe_name(self, cpe_name: str) -> Optional[Dict[str, str]]:
        """Parse CPE 2.3 format name into components"""
        if not cpe_name.startswith('cpe:2.3:'):
            return None
        
        parts = cpe_name.split(':')
        if len(parts) < 7:
            return None
        
        return {
            'part': parts[2],        # a=application, o=os, h=hardware
            'vendor': parts[3],      # vendor name
            'product': parts[4],     # product name
            'version': parts[5],     # version
            'update': parts[6],      # update
            'edition': parts[7] if len(parts) > 7 else '*',
            'language': parts[8] if len(parts) > 8 else '*'
        }
    
    async def _find_potential_cves(self, cpe_parts: Dict[str, str]) -> List[CVE]:
        """Find CVEs that might affect the given CPE components"""
        vendor = cpe_parts['vendor']
        product = cpe_parts['product']
        
        # Build search conditions
        conditions = []
        
        # Search in CVE description
        if vendor != '*':
            conditions.append(CVE.description.ilike(f'%{vendor}%'))
        
        if product != '*':
            conditions.append(CVE.description.ilike(f'%{product}%'))
        
        # Search in affected_products JSON field
        if vendor != '*' or product != '*':
            vendor_condition = f'"vendor": "{vendor}"' if vendor != '*' else None
            product_condition = f'"product": "{product}"' if product != '*' else None
            
            if vendor_condition:
                conditions.append(CVE.affected_products.ilike(f'%{vendor_condition}%'))
            if product_condition:
                conditions.append(CVE.affected_products.ilike(f'%{product_condition}%'))
        
        # Search in CPE entries
        cpe_search = f'{vendor}:{product}' if vendor != '*' and product != '*' else (vendor if vendor != '*' else product)
        if cpe_search != '*':
            conditions.append(CVE.cpe_entries.ilike(f'%{cpe_search}%'))
        
        if not conditions:
            return []
        
        # Execute query with OR conditions
        cves = self.db.query(CVE).filter(or_(*conditions)).limit(1000).all()
        return cves
    
    async def _match_cpe_to_cve(self, cpe_name: str, cpe_parts: Dict[str, str], 
                               cve: CVE, include_version_range: bool) -> List[CPECVEMatch]:
        """Match a specific CPE to a CVE with confidence scoring"""
        matches = []
        
        vendor = cpe_parts['vendor']
        product = cpe_parts['product']
        version = cpe_parts['version']
        
        # Check CVE description match
        desc_match = self._check_description_match(cve.description, vendor, product)
        if desc_match['score'] > 0.3:
            matches.append(CPECVEMatch(
                cpe_name=cpe_name,
                cpe_name_id='',  # Would need to be populated from CPE lookup
                cve_id=cve.cve_id,
                match_type='description',
                confidence_score=desc_match['score'],
                match_details=desc_match
            ))
        
        # Check affected_products JSON field
        if cve.affected_products:
            affected_match = self._check_affected_products_match(
                cve.affected_products, vendor, product, version, include_version_range
            )
            if affected_match['score'] > 0.5:
                matches.append(CPECVEMatch(
                    cpe_name=cpe_name,
                    cpe_name_id='',
                    cve_id=cve.cve_id,
                    match_type='affected_products',
                    confidence_score=affected_match['score'],
                    version_affected=affected_match.get('version_affected'),
                    match_details=affected_match
                ))
        
        # Check CPE entries
        if cve.cpe_entries:
            cpe_match = self._check_cpe_entries_match(
                cve.cpe_entries, cpe_name, vendor, product, version, include_version_range
            )
            if cpe_match['score'] > 0.7:
                matches.append(CPECVEMatch(
                    cpe_name=cpe_name,
                    cpe_name_id='',
                    cve_id=cve.cve_id,
                    match_type='cpe_exact',
                    confidence_score=cpe_match['score'],
                    version_affected=cpe_match.get('version_affected'),
                    match_details=cpe_match
                ))
        
        return matches
    
    def _check_description_match(self, description: str, vendor: str, product: str) -> Dict:
        """Check if CVE description mentions the vendor/product"""
        if not description:
            return {'score': 0.0}
        
        desc_lower = description.lower()
        score = 0.0
        details = {'matched_terms': []}
        
        if vendor != '*' and vendor.lower() in desc_lower:
            score += 0.4
            details['matched_terms'].append(f'vendor: {vendor}')
        
        if product != '*' and product.lower() in desc_lower:
            score += 0.5
            details['matched_terms'].append(f'product: {product}')
        
        # Boost score if both vendor and product are mentioned close together
        if vendor != '*' and product != '*':
            vendor_pos = desc_lower.find(vendor.lower())
            product_pos = desc_lower.find(product.lower())
            if vendor_pos != -1 and product_pos != -1 and abs(vendor_pos - product_pos) < 50:
                score += 0.2
                details['proximity_boost'] = True
        
        return {'score': min(score, 1.0), **details}
    
    def _check_affected_products_match(self, affected_products: any, vendor: str, 
                                     product: str, version: str, include_version_range: bool) -> Dict:
        """Check affected_products JSON field for matches"""
        try:
            if isinstance(affected_products, str):
                products = json.loads(affected_products)
            else:
                products = affected_products
            
            if not isinstance(products, list):
                return {'score': 0.0}
            
            best_match = {'score': 0.0}
            
            for product_entry in products:
                if not isinstance(product_entry, dict):
                    continue
                
                entry_vendor = product_entry.get('vendor', '').lower()
                entry_product = product_entry.get('product', '').lower()
                entry_version = product_entry.get('version', '')
                
                match_score = 0.0
                match_details = {}
                
                # Vendor match
                if vendor != '*' and vendor.lower() == entry_vendor:
                    match_score += 0.4
                elif vendor != '*' and vendor.lower() in entry_vendor:
                    match_score += 0.2
                
                # Product match
                if product != '*' and product.lower() == entry_product:
                    match_score += 0.5
                elif product != '*' and product.lower() in entry_product:
                    match_score += 0.3
                
                # Version match if requested
                if include_version_range and version != '*' and entry_version:
                    version_match = self._check_version_match(version, entry_version, product_entry)
                    match_score += version_match['score'] * 0.3
                    match_details.update(version_match)
                
                if match_score > best_match['score']:
                    best_match = {
                        'score': min(match_score, 1.0),
                        'matched_entry': product_entry,
                        **match_details
                    }
            
            return best_match
            
        except (json.JSONDecodeError, TypeError):
            return {'score': 0.0}
    
    def _check_cpe_entries_match(self, cpe_entries: any, target_cpe: str, vendor: str, 
                               product: str, version: str, include_version_range: bool) -> Dict:
        """Check CPE entries for exact or partial matches"""
        try:
            if isinstance(cpe_entries, str):
                entries = json.loads(cpe_entries)
            else:
                entries = cpe_entries
            
            if not isinstance(entries, list):
                return {'score': 0.0}
            
            best_match = {'score': 0.0}
            
            for entry_cpe in entries:
                if not isinstance(entry_cpe, str) or not entry_cpe.startswith('cpe:'):
                    continue
                
                # Exact match
                if entry_cpe == target_cpe:
                    return {
                        'score': 1.0,
                        'match_type': 'exact',
                        'matched_cpe': entry_cpe
                    }
                
                # Parse entry CPE for partial matching
                entry_parts = self.parse_cpe_name(entry_cpe)
                if not entry_parts:
                    continue
                
                match_score = 0.0
                match_details = {'matched_cpe': entry_cpe}
                
                # Component matching
                if vendor != '*' and entry_parts['vendor'] == vendor:
                    match_score += 0.4
                elif vendor != '*' and vendor in entry_parts['vendor']:
                    match_score += 0.2
                
                if product != '*' and entry_parts['product'] == product:
                    match_score += 0.5
                elif product != '*' and product in entry_parts['product']:
                    match_score += 0.3
                
                # Version matching
                if include_version_range and version != '*' and entry_parts['version'] != '*':
                    version_match = self._compare_versions(version, entry_parts['version'])
                    match_score += version_match * 0.3
                    match_details['version_match'] = version_match
                
                if match_score > best_match['score']:
                    best_match = {
                        'score': min(match_score, 1.0),
                        'match_type': 'partial',
                        **match_details
                    }
            
            return best_match
            
        except (json.JSONDecodeError, TypeError):
            return {'score': 0.0}
    
    def _check_version_match(self, target_version: str, entry_version: str, product_entry: Dict) -> Dict:
        """Check if target version is affected by CVE version specification"""
        # Check for version ranges
        version_start = product_entry.get('version_start')
        version_end = product_entry.get('version_end')
        
        if version_start or version_end:
            return self._check_version_range(target_version, version_start, version_end)
        
        # Direct version comparison
        if target_version == entry_version:
            return {'score': 1.0, 'match_type': 'exact'}
        
        # Semantic version comparison
        comparison_score = self._compare_versions(target_version, entry_version)
        return {'score': comparison_score, 'match_type': 'version_similarity'}
    
    def _check_version_range(self, target_version: str, version_start: str, version_end: str) -> Dict:
        """Check if target version falls within affected range"""
        try:
            target_parts = self._parse_version(target_version)
            if not target_parts:
                return {'score': 0.0}
            
            in_range = True
            range_details = {}
            
            if version_start:
                start_parts = self._parse_version(version_start)
                if start_parts and self._compare_version_parts(target_parts, start_parts) < 0:
                    in_range = False
                range_details['version_start'] = version_start
            
            if version_end and in_range:
                end_parts = self._parse_version(version_end)
                if end_parts and self._compare_version_parts(target_parts, end_parts) > 0:
                    in_range = False
                range_details['version_end'] = version_end
            
            return {
                'score': 1.0 if in_range else 0.0,
                'match_type': 'version_range',
                'in_range': in_range,
                **range_details
            }
            
        except Exception:
            return {'score': 0.0}
    
    def _parse_version(self, version: str) -> Optional[Tuple[int, ...]]:
        """Parse version string into comparable tuple"""
        if not version or version == '*':
            return None
        
        # Clean version string
        clean_version = re.sub(r'[^\d.]', '', version)
        
        try:
            parts = []
            for part in clean_version.split('.'):
                if part.isdigit():
                    parts.append(int(part))
                else:
                    break
            return tuple(parts) if parts else None
        except:
            return None
    
    def _compare_version_parts(self, v1: Tuple[int, ...], v2: Tuple[int, ...]) -> int:
        """Compare two version tuples (-1, 0, 1)"""
        # Pad shorter version with zeros
        max_len = max(len(v1), len(v2))
        v1_padded = v1 + (0,) * (max_len - len(v1))
        v2_padded = v2 + (0,) * (max_len - len(v2))
        
        for a, b in zip(v1_padded, v2_padded):
            if a < b:
                return -1
            elif a > b:
                return 1
        return 0
    
    def _compare_versions(self, v1: str, v2: str) -> float:
        """Compare versions and return similarity score (0-1)"""
        v1_parts = self._parse_version(v1)
        v2_parts = self._parse_version(v2)
        
        if not v1_parts or not v2_parts:
            return 0.0
        
        if v1_parts == v2_parts:
            return 1.0
        
        # Calculate similarity based on common prefix
        common_parts = 0
        min_len = min(len(v1_parts), len(v2_parts))
        
        for i in range(min_len):
            if v1_parts[i] == v2_parts[i]:
                common_parts += 1
            else:
                break
        
        # Similarity based on common prefix ratio
        return common_parts / max(len(v1_parts), len(v2_parts))
    
    def _get_cve_cvss(self, cve_id: str) -> Optional[float]:
        """Get CVSS score for a CVE"""
        cve = self.db.query(CVE).filter(CVE.cve_id == cve_id).first()
        return cve.get_primary_cvss_score() if cve else None
    
    def _calculate_overall_confidence(self, assessment: AssetVulnerabilityAssessment) -> float:
        """Calculate overall correlation confidence for an asset"""
        if assessment.total_cves == 0:
            return 0.0
        
        # Weight by severity - higher severity CVEs increase confidence
        weighted_score = (
            assessment.critical_cves * 1.0 +
            assessment.high_cves * 0.8 +
            assessment.medium_cves * 0.6 +
            assessment.low_cves * 0.4
        )
        
        return min(weighted_score / (assessment.total_cves * 1.0), 1.0)
    
    def _generate_recommendations(self, asset: Asset, matches: List[CPECVEMatch], 
                                affected_services: List[Dict]) -> List[str]:
        """Generate actionable recommendations based on vulnerabilities"""
        recommendations = []
        
        if not matches:
            recommendations.append("No known vulnerabilities found for current asset configuration.")
            return recommendations
        
        # Count high-confidence, high-severity matches
        critical_matches = [m for m in matches if m.confidence_score > 0.8]
        
        if critical_matches:
            recommendations.append(f"URGENT: {len(critical_matches)} high-confidence vulnerabilities identified.")
        
        # Service-specific recommendations
        for service in affected_services:
            if service['highest_cvss'] >= 7.0:
                recommendations.append(
                    f"Consider updating {service['service_name']} - {service['cve_count']} vulnerabilities found."
                )
        
        # Environment-specific recommendations
        if asset.environment == 'production' and any(m.confidence_score > 0.8 for m in matches):
            recommendations.append("Production asset with high-confidence vulnerabilities requires immediate attention.")
        
        # Asset criticality recommendations
        if asset.criticality in ['critical', 'high'] and matches:
            recommendations.append(f"Critical asset with {len(matches)} potential vulnerabilities needs priority review.")
        
        return recommendations
    
    async def get_cpe_vulnerability_summary(self, cpe_name: str) -> Dict[str, any]:
        """Get vulnerability summary for a specific CPE"""
        matches = await self.correlate_cpe_to_cves(cpe_name)
        
        if not matches:
            return {
                'cpe_name': cpe_name,
                'total_cves': 0,
                'severity_breakdown': {},
                'confidence_levels': {},
                'latest_cve': None,
                'recommendations': ["No known vulnerabilities found for this CPE."]
            }
        
        # Analyze matches
        severity_counts = defaultdict(int)
        confidence_counts = defaultdict(int)
        latest_cve_date = None
        latest_cve = None
        
        for match in matches:
            cve = self.db.query(CVE).filter(CVE.cve_id == match.cve_id).first()
            if cve:
                severity = (cve.severity or 'unknown').lower()
                severity_counts[severity] += 1
                
                if cve.published_date:
                    if not latest_cve_date or cve.published_date > latest_cve_date:
                        latest_cve_date = cve.published_date
                        latest_cve = cve.cve_id
                
                # Confidence levels
                if match.confidence_score >= 0.8:
                    confidence_counts['high'] += 1
                elif match.confidence_score >= 0.6:
                    confidence_counts['medium'] += 1
                else:
                    confidence_counts['low'] += 1
        
        return {
            'cpe_name': cpe_name,
            'total_cves': len(matches),
            'severity_breakdown': dict(severity_counts),
            'confidence_levels': dict(confidence_counts),
            'latest_cve': latest_cve,
            'latest_cve_date': latest_cve_date.isoformat() if latest_cve_date else None,
            'high_confidence_matches': confidence_counts['high'],
            'recommendations': self._generate_cpe_recommendations(cpe_name, matches, dict(severity_counts))
        }
    
    def _generate_cpe_recommendations(self, cpe_name: str, matches: List[CPECVEMatch], 
                                    severity_counts: Dict[str, int]) -> List[str]:
        """Generate recommendations for a CPE"""
        recommendations = []
        
        if severity_counts.get('critical', 0) > 0:
            recommendations.append("CRITICAL: This software has critical vulnerabilities. Update immediately.")
        
        if severity_counts.get('high', 0) > 0:
            recommendations.append("HIGH: This software has high-severity vulnerabilities. Plan updates.")
        
        total_vulns = sum(severity_counts.values())
        if total_vulns > 10:
            recommendations.append(f"This software has {total_vulns} known vulnerabilities. Consider alternatives.")
        
        high_confidence = len([m for m in matches if m.confidence_score > 0.8])
        if high_confidence > 0:
            recommendations.append(f"{high_confidence} vulnerabilities have high confidence matches.")
        
        return recommendations or ["Monitor for new vulnerabilities."]


# Utility functions for API integration
async def correlate_asset_vulnerabilities(db: Session, asset_id: int) -> AssetVulnerabilityAssessment:
    """API utility function to correlate vulnerabilities for an asset"""
    engine = CPECVECorrelationEngine(db)
    return await engine.assess_asset_vulnerabilities(asset_id)

async def get_cpe_vulnerabilities(db: Session, cpe_name: str) -> Dict[str, any]:
    """API utility function to get vulnerabilities for a CPE"""
    engine = CPECVECorrelationEngine(db)
    return await engine.get_cpe_vulnerability_summary(cpe_name)

async def bulk_assess_infrastructure(db: Session, asset_ids: Optional[List[int]] = None) -> Dict[str, any]:
    """API utility function for bulk vulnerability assessment"""
    engine = CPECVECorrelationEngine(db)
    return await engine.bulk_correlate_assets(asset_ids)