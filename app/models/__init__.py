# Import all models to ensure they're registered with SQLAlchemy
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
