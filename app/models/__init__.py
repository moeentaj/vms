"""
Cleaned Models Package - Asset-Based Architecture Only
app/models/__init__.py

Import only asset-based models, removing all service-based dependencies.
"""

# Core models for asset-based vulnerability management
from .user import User
from .cve import CVE
from .asset import Asset
from .vulnerability_assignment import VulnerabilityAssignment, AssignmentStatus, AssignmentPriority

# This ensures all models are available when the package is imported
__all__ = [
    "User",
    "CVE", 
    "Asset",
    "VulnerabilityAssignment",
    "AssignmentStatus",
    "AssignmentPriority"
]

# Note: Removed service-based imports:
# - ServiceCategory, ServiceType, ServiceInstance
# - ProductMapping, CorrelationRule
# - Any other service-related models