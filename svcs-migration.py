"""
Migration script to convert existing assets to the new service-oriented hierarchy.
This script will:
1. Create default service categories
2. Create service types based on existing asset types
3. Convert existing assets to service instances
4. Preserve all existing data while adding the hierarchical structure
"""

from sqlalchemy.orm import Session
from app.core.database import get_db, engine
from app.models.asset import Asset
from app.models.service import ServiceCategory, ServiceType, ServiceInstance
import json
from datetime import datetime

# Default service categories to create
DEFAULT_CATEGORIES = [
    {
        'name': 'Web Servers',
        'description': 'HTTP/HTTPS web servers and reverse proxies',
        'icon': 'server'
    },
    {
        'name': 'Databases',
        'description': 'Database management systems',
        'icon': 'database'
    },
    {
        'name': 'Operating Systems',
        'description': 'Server and workstation operating systems',
        'icon': 'monitor'
    },
    {
        'name': 'Applications',
        'description': 'Business applications and services',
        'icon': 'folder'
    },
    {
        'name': 'Network Devices',
        'description': 'Routers, switches, firewalls, and other network equipment',
        'icon': 'network'
    },
    {
        'name': 'Security Services',
        'description': 'Security tools and monitoring services',
        'icon': 'shield'
    }
]

# Mapping of asset types to service categories and specific service types
ASSET_TYPE_MAPPING = {
    'server': {
        'category': 'Operating Systems',
        'service_types': {
            'Windows Server': {
                'vendor': 'Microsoft',
                'description': 'Windows Server operating system',
                'default_ports': '3389,135,139,445'
            },
            'Linux Server': {
                'vendor': 'Various',
                'description': 'Linux-based server operating system',
                'default_ports': '22,80,443'
            },
            'Unix Server': {
                'vendor': 'Various',
                'description': 'Unix-based server operating system',
                'default_ports': '22'
            }
        }
    },
    'database': {
        'category': 'Databases',
        'service_types': {
            'MySQL': {
                'vendor': 'Oracle',
                'description': 'MySQL database server',
                'default_ports': '3306'
            },
            'PostgreSQL': {
                'vendor': 'PostgreSQL Global Development Group',
                'description': 'PostgreSQL database server',
                'default_ports': '5432'
            },
            'Microsoft SQL Server': {
                'vendor': 'Microsoft',
                'description': 'Microsoft SQL Server database',
                'default_ports': '1433'
            },
            'Oracle Database': {
                'vendor': 'Oracle',
                'description': 'Oracle Database server',
                'default_ports': '1521'
            }
        }
    },
    'application': {
        'category': 'Applications',
        'service_types': {
            'Web Application': {
                'vendor': 'Various',
                'description': 'Generic web application',
                'default_ports': '80,443,8080'
            },
            'API Service': {
                'vendor': 'Various',
                'description': 'REST/GraphQL API service',
                'default_ports': '80,443,8080'
            }
        }
    },
    'network': {
        'category': 'Network Devices',
        'service_types': {
            'Router': {
                'vendor': 'Various',
                'description': 'Network router',
                'default_ports': '22,80,443,161'
            },
            'Switch': {
                'vendor': 'Various',
                'description': 'Network switch',
                'default_ports': '22,80,443,161'
            },
            'Firewall': {
                'vendor': 'Various',
                'description': 'Network firewall',
                'default_ports': '22,80,443,161'
            }
        }
    },
    'workstation': {
        'category': 'Operating Systems',
        'service_types': {
            'Windows Workstation': {
                'vendor': 'Microsoft',
                'description': 'Windows desktop/workstation',
                'default_ports': '3389,135,139,445'
            },
            'macOS Workstation': {
                'vendor': 'Apple',
                'description': 'macOS desktop/workstation',
                'default_ports': '22,5900'
            },
            'Linux Workstation': {
                'vendor': 'Various',
                'description': 'Linux desktop/workstation',
                'default_ports': '22'
            }
        }
    }
}

def create_service_tables():
    """Create the new service tables"""
    from app.models.service import Base
    Base.metadata.create_all(bind=engine)
    print("✓ Created service tables")

def create_default_categories(db: Session):
    """Create default service categories"""
    created_categories = {}
    
    for category_data in DEFAULT_CATEGORIES:
        # Check if category already exists
        existing = db.query(ServiceCategory).filter(
            ServiceCategory.name == category_data['name']
        ).first()
        
        if not existing:
            category = ServiceCategory(**category_data)
            db.add(category)
            db.flush()  # Get the ID without committing
            created_categories[category.name] = category
            print(f"✓ Created category: {category.name}")
        else:
            created_categories[existing.name] = existing
            print(f"- Category already exists: {existing.name}")
    
    return created_categories

def create_service_types(db: Session, categories):
    """Create service types based on asset type mapping"""
    created_service_types = {}
    
    for asset_type, mapping in ASSET_TYPE_MAPPING.items():
        category_name = mapping['category']
        category = categories.get(category_name)
        
        if not category:
            print(f"⚠ Warning: Category '{category_name}' not found for asset type '{asset_type}'")
            continue
        
        for service_name, service_data in mapping['service_types'].items():
            # Check if service type already exists
            existing = db.query(ServiceType).filter(
                ServiceType.name == service_name,
                ServiceType.category_id == category.id
            ).first()
            
            if not existing:
                service_type = ServiceType(
                    category_id=category.id,
                    name=service_name,
                    **service_data
                )
                db.add(service_type)
                db.flush()
                created_service_types[f"{asset_type}:{service_name}"] = service_type
                print(f"✓ Created service type: {service_name} in {category_name}")
            else:
                created_service_types[f"{asset_type}:{service_name}"] = existing
                print(f"- Service type already exists: {service_name}")
    
    return created_service_types

def migrate_assets_to_services(db: Session, service_types):
    """Convert existing assets to service instances"""
    assets = db.query(Asset).all()
    migrated_count = 0
    
    for asset in assets:
        # Determine the appropriate service type
        service_type = None
        asset_type = asset.asset_type.lower()
        
        # Try to find a matching service type
        for key, st in service_types.items():
            if key.startswith(asset_type + ":"):
                service_type = st
                break
        
        # If no specific match, try to infer from asset properties
        if not service_type:
            if asset_type == 'server':
                # Try to determine OS from asset name or other properties
                if any(keyword in asset.name.lower() for keyword in ['windows', 'win', 'w2k']):
                    service_type = service_types.get('server:Windows Server')
                else:
                    service_type = service_types.get('server:Linux Server')
            elif asset_type == 'database':
                # Try to determine database type from name
                if 'mysql' in asset.name.lower():
                    service_type = service_types.get('database:MySQL')
                elif 'postgres' in asset.name.lower():
                    service_type = service_types.get('database:PostgreSQL')
                elif 'sql server' in asset.name.lower() or 'mssql' in asset.name.lower():
                    service_type = service_types.get('database:Microsoft SQL Server')
                elif 'oracle' in asset.name.lower():
                    service_type = service_types.get('database:Oracle Database')
                else:
                    service_type = service_types.get('database:MySQL')  # Default
            else:
                # Use the first service type for this asset category
                for key, st in service_types.items():
                    if key.startswith(asset_type + ":"):
                        service_type = st
                        break
        
        if not service_type:
            print(f"⚠ Warning: Could not find service type for asset '{asset.name}' of type '{asset_type}'")
            continue
        
        # Check if service instance already exists (to avoid duplicates)
        existing_instance = db.query(ServiceInstance).filter(
            ServiceInstance.name == asset.name,
            ServiceInstance.service_type_id == service_type.id
        ).first()
        
        if existing_instance:
            print(f"- Service instance already exists: {asset.name}")
            continue
        
        # Create service instance from asset
        instance = ServiceInstance(
            service_type_id=service_type.id,
            name=asset.name,
            version=asset.version,
            environment=asset.environment,
            criticality=asset.criticality,
            hostname=asset.name if not asset.ip_address else None,  # Use name as hostname if no IP
            ip_addresses=asset.ip_address,
            location=None,  # Will need to be filled manually
            owner_team=None,  # Will need to be filled manually
            contact_email=None,  # Will need to be filled manually
            status='active',
            is_monitored=True,
            tags=asset.tags,  # Preserve existing tags
            notes=f"Migrated from asset ID {asset.id}",
            created_at=asset.created_at,
            updated_at=asset.updated_at,
            last_scan_date=asset.last_scan
        )
        
        db.add(instance)
        migrated_count += 1
        print(f"✓ Migrated asset '{asset.name}' to service instance")
    
    return migrated_count

def run_migration():
    """Main migration function"""
    print("Starting migration from assets to services...")
    print("=" * 50)
    
    # Create tables
    create_service_tables()
    
    # Get database session
    db = next(get_db())
    
    try:
        # Step 1: Create default categories
        print("\n1. Creating service categories...")
        categories = create_default_categories(db)
        
        # Step 2: Create service types
        print("\n2. Creating service types...")
        service_types = create_service_types(db, categories)
        
        # Step 3: Migrate assets to service instances
        print("\n3. Migrating assets to service instances...")
        migrated_count = migrate_assets_to_services(db, service_types)
        
        # Commit all changes
        db.commit()
        
        print("\n" + "=" * 50)
        print("Migration completed successfully!")
        print(f"✓ Created {len(categories)} service categories")
        print(f"✓ Created {len(service_types)} service types")
        print(f"✓ Migrated {migrated_count} assets to service instances")
        print("\nNext steps:")
        print("1. Review the migrated service instances and fill in missing information")
        print("2. Add additional service types as needed for your environment")
        print("3. Consider archiving the old assets table once migration is verified")
        
    except Exception as e:
        print(f"\n❌ Migration failed: {str(e)}")
        db.rollback()
        raise
    finally:
        db.close()

def verify_migration():
    """Verify the migration results"""
    db = next(get_db())
    
    try:
        category_count = db.query(ServiceCategory).count()
        service_type_count = db.query(ServiceType).count()
        instance_count = db.query(ServiceInstance).count()
        asset_count = db.query(Asset).count()
        
        print("\nMigration verification:")
        print(f"- Service categories: {category_count}")
        print(f"- Service types: {service_type_count}")
        print(f"- Service instances: {instance_count}")
        print(f"- Original assets: {asset_count}")
        
        # Show breakdown by category
        print("\nBreakdown by category:")
        categories = db.query(ServiceCategory).all()
        for category in categories:
            type_count = len(category.service_types)
            instance_count = sum(len(st.service_instances) for st in category.service_types)
            print(f"- {category.name}: {type_count} types, {instance_count} instances")
            
    finally:
        db.close()

if __name__ == "__main__":
    # Run the migration
    run_migration()
    
    # Verify results
    verify_migration()