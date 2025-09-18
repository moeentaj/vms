"""
Enhanced Asset Model with CPE Service Integration
app/models/asset.py
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON, Float
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import ENUM
from app.core.database import Base
import enum

class DataSourceType(enum.Enum):
    """Enumeration of supported data sources"""
    MANUAL = "manual"
    CPE = "cpe"
    NMAP = "nmap"
    NESSUS = "nessus"
    CUSTOM_AGENT = "custom_agent"
    IMPORT = "import"

# Create PostgreSQL ENUM type
data_source_enum = ENUM(
    'manual',
    'cpe', 
    'nmap',
    'nessus',
    'custom_agent',
    'import',
    name='datasourcetype',
    create_type=False
)

class Asset(Base):
    """Enhanced Asset model with CPE service integration"""
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    asset_type = Column(String(50), nullable=False)  # server, service, application, network_device
    
    # Network information
    ip_address = Column(String(45), nullable=True)
    hostname = Column(String(255), nullable=True)
    mac_address = Column(String(17), nullable=True)
    
    # Service/Software information (CPE integrated)
    primary_service = Column(String(200), nullable=True)  # Main service running on this asset
    service_vendor = Column(String(100), nullable=True)
    service_version = Column(String(100), nullable=True)
    
    # CPE Reference fields
    cpe_name = Column(String(500), nullable=True)  # Full CPE name if identified via CPE
    cpe_name_id = Column(String(100), nullable=True)  # NIST CPE UUID
    cpe_product = Column(String(100), nullable=True)  # CPE product identifier
    
    # Additional services running on this asset
    additional_services = Column(JSON, nullable=True)  # Array of service objects with CPE refs
    
    # Asset metadata
    vendor = Column(String(100), nullable=True)  # Asset vendor (Dell, HP, etc.)
    model = Column(String(100), nullable=True)   # Asset model
    serial_number = Column(String(100), nullable=True)
    
    # Environment and criticality
    environment = Column(String(50), nullable=False, default="production")
    criticality = Column(String(20), default="medium")  # low, medium, high, critical
    
    # Operating System
    operating_system = Column(String(100), nullable=True)
    os_version = Column(String(50), nullable=True)
    os_cpe_name = Column(String(500), nullable=True)  # CPE for OS
    
    # Location and ownership
    location = Column(String(100), nullable=True)
    owner_team = Column(String(100), nullable=True)
    contact_email = Column(String(255), nullable=True)
    business_unit = Column(String(100), nullable=True)
    
    # Network and port information
    open_ports = Column(JSON, nullable=True)  # Array of port objects
    network_segment = Column(String(100), nullable=True)
    
    # Data source tracking
    data_source = Column(data_source_enum, default='manual', nullable=False)
    source_reference = Column(String(500), nullable=True)
    discovery_timestamp = Column(DateTime, nullable=True)
    
    # Confidence and validation
    detection_confidence = Column(Float, nullable=True)
    manual_verification = Column(Boolean, default=False)
    verification_notes = Column(Text, nullable=True)
    
    # Status and monitoring
    status = Column(String(20), default="active")  # active, inactive, decommissioned
    is_monitored = Column(Boolean, default=True)
    monitoring_agent = Column(String(100), nullable=True)
    
    # Vulnerability and compliance
    last_vulnerability_scan = Column(DateTime, nullable=True)
    vulnerability_score = Column(Float, nullable=True)
    compliance_status = Column(String(50), nullable=True)
    
    # Additional metadata
    tags = Column(JSON, nullable=True)  # Flexible tagging
    custom_fields = Column(JSON, nullable=True)  # Extensible metadata
    notes = Column(Text, nullable=True)
    
    # Audit fields
    created_by = Column(String(100), nullable=True)
    last_modified_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    last_scan = Column(DateTime, nullable=True)
    
    def get_primary_service_display(self):
        """Get display name for primary service"""
        if self.primary_service:
            if self.service_vendor:
                return f"{self.service_vendor} {self.primary_service}"
            return self.primary_service
        return "No primary service identified"
    
    def get_additional_services_list(self):
        """Get additional services as a list"""
        if self.additional_services:
            return self.additional_services
        return []
    
    def add_service_from_cpe(self, cpe_product_data, is_primary=False):
        """Add service information from CPE product data"""
        if is_primary:
            self.primary_service = cpe_product_data.get('product', '')
            self.service_vendor = cpe_product_data.get('vendor', '')
            self.service_version = cpe_product_data.get('version', '')
            self.cpe_name = cpe_product_data.get('cpe_name', '')
            self.cpe_name_id = cpe_product_data.get('cpe_name_id', '')
            self.cpe_product = cpe_product_data.get('product', '')
        else:
            # Add to additional services
            if not self.additional_services:
                self.additional_services = []
            
            service_entry = {
                'name': cpe_product_data.get('product', ''),
                'vendor': cpe_product_data.get('vendor', ''),
                'version': cpe_product_data.get('version', ''),
                'cpe_name': cpe_product_data.get('cpe_name', ''),
                'cpe_name_id': cpe_product_data.get('cpe_name_id', ''),
                'ports': cpe_product_data.get('ports', []),
                'detection_method': 'cpe_lookup'
            }
            self.additional_services.append(service_entry)
    
    def get_all_cpe_references(self):
        """Get all CPE references for this asset"""
        cpe_refs = []
        
        # Primary service CPE
        if self.cpe_name:
            cpe_refs.append({
                'type': 'primary_service',
                'cpe_name': self.cpe_name,
                'cpe_name_id': self.cpe_name_id,
                'product': self.primary_service,
                'vendor': self.service_vendor
            })
        
        # OS CPE
        if self.os_cpe_name:
            cpe_refs.append({
                'type': 'operating_system',
                'cpe_name': self.os_cpe_name,
                'product': self.operating_system,
                'vendor': None
            })
        
        # Additional services CPE
        if self.additional_services:
            for service in self.additional_services:
                if service.get('cpe_name'):
                    cpe_refs.append({
                        'type': 'additional_service',
                        'cpe_name': service['cpe_name'],
                        'cpe_name_id': service.get('cpe_name_id'),
                        'product': service['name'],
                        'vendor': service.get('vendor')
                    })
        
        return cpe_refs
    
    def get_data_source_display(self):
        """Get human-readable data source name"""
        source_names = {
            'manual': "Manual Entry",
            'cpe': "NIST CPE Database",
            'nmap': "Nmap Discovery",
            'nessus': "Nessus Scanner",
            'custom_agent': "Custom Agent",
            'import': "Data Import"
        }
        return source_names.get(self.data_source, str(self.data_source))
    
    def get_tags_list(self):
        """Get tags as a list"""
        if self.tags:
            return self.tags
        return []
    
    def set_tags(self, tag_list):
        """Set tags from a list"""
        if isinstance(tag_list, list):
            self.tags = tag_list
        elif isinstance(tag_list, str):
            self.tags = [tag.strip() for tag in tag_list.split(',') if tag.strip()]