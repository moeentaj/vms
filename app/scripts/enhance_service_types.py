# scripts/enhance_service_types.py
from app.core.database import SessionLocal
from app.models.service import ServiceType
import json

def enhance_service_types():
    db = SessionLocal()
    
    # Common service mappings
    service_mappings = {
        'Apache HTTP Server': {
            'product_name': 'httpd',
            'vendor_aliases': ['Apache Software Foundation', 'Apache'],
            'product_aliases': ['apache', 'httpd', 'apache2']
        },
        'Nginx': {
            'product_name': 'nginx',
            'vendor_aliases': ['Nginx Inc.', 'nginx'],
            'product_aliases': ['nginx', 'nginx-server']
        },
        'MySQL': {
            'product_name': 'mysql',
            'vendor_aliases': ['MySQL AB'],
            'product_aliases': ['mysql-server', 'mysql-community']
        },
        'PostgreSQL': {
            'product_name': 'postgresql',
            'vendor_aliases': ['PostgreSQL Global Development Group'],
            'product_aliases': ['postgres', 'postgresql-server']
        },
        'Microsoft IIS': {
            'product_name': 'iis',
            'vendor_aliases': ['Microsoft Corporation'],
            'product_aliases': ['internet_information_services', 'iis-server']
        }
    }
    
    service_types = db.query(ServiceType).all()
    
    for service_type in service_types:
        if service_type.name in service_mappings:
            mapping = service_mappings[service_type.name]
            service_type.product_name = mapping['product_name']
            service_type.vendor_aliases = json.dumps(mapping['vendor_aliases'])
            service_type.product_aliases = json.dumps(mapping['product_aliases'])
            
            print(f"Enhanced service type: {service_type.name}")
    
    db.commit()
    db.close()
    print("Service type enhancement completed")

if __name__ == "__main__":
    enhance_service_types()
