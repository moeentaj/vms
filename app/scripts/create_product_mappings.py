# scripts/create_product_mappings.py
from app.core.database import SessionLocal
from app.models.correlation import ProductMapping
from app.models.service import ServiceType

def create_initial_mappings():
    db = SessionLocal()
    
    # Common NVD to service type mappings
    nvd_mappings = [
        ('apache', 'http_server', 'Apache HTTP Server'),
        ('nginx', 'nginx', 'Nginx'),
        ('oracle', 'mysql', 'MySQL'),
        ('postgresql', 'postgresql', 'PostgreSQL'),
        ('microsoft', 'iis', 'Microsoft IIS'),
        ('docker', 'docker', 'Docker'),
        ('kubernetes', 'kubernetes', 'Kubernetes'),
    ]
    
    for vendor, product, service_name in nvd_mappings:
        # Find matching service type
        service_type = db.query(ServiceType).filter(
            ServiceType.name == service_name
        ).first()
        
        if service_type:
            mapping = ProductMapping(
                source_vendor=vendor,
                source_product=product,
                source_type='nvd',
                target_service_type_id=service_type.id,
                confidence=0.9,
                verified=True,
                notes=f"Initial mapping for {service_name}"
            )
            db.add(mapping)
            print(f"Created mapping: {vendor}/{product} -> {service_name}")
    
    db.commit()
    db.close()
    print("Product mappings created")

if __name__ == "__main__":
    create_initial_mappings()