#!/usr/bin/env python3
"""
Database Cleanup Script - Remove Service-Based Tables
scripts/cleanup_service_tables.py

This script removes all service-based tables and data, keeping only asset-based architecture.
Run this after backing up your database.

Usage:
    python scripts/cleanup_service_tables.py
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sqlalchemy import create_engine, text, MetaData, inspect
from sqlalchemy.exc import SQLAlchemyError
from app.core.database import get_db_url
from app.core.config import settings
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Tables to remove (service-based architecture)
SERVICE_TABLES_TO_REMOVE = [
    'service_instances',
    'service_types', 
    'service_categories',
    'product_mappings',
    'correlation_rules',
    'service_correlations',
    'service_vulnerabilities',
    'asset_service_mappings'  # If this exists
]

# Columns to remove from existing tables
COLUMNS_TO_REMOVE = {
    'cves': [
        'affects_service_types',  # Remove service-based correlation
        'service_correlation_confidence'
    ],
    'assets': [
        'service_instance_id',  # Remove service FK if exists
        'mapped_service_type_id'
    ]
}

def get_database_engine():
    """Get database engine"""
    try:
        db_url = get_db_url()
        engine = create_engine(db_url)
        logger.info(f"Connected to database: {db_url.split('@')[-1]}")  # Hide credentials
        return engine
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        raise

def backup_reminder():
    """Remind user to backup database"""
    print("\n" + "="*60)
    print("🔴 IMPORTANT: DATABASE CLEANUP WARNING")
    print("="*60)
    print("This script will PERMANENTLY DELETE service-based tables and data!")
    print("\nTables to be removed:")
    for table in SERVICE_TABLES_TO_REMOVE:
        print(f"  - {table}")
    print("\nColumns to be removed:")
    for table, columns in COLUMNS_TO_REMOVE.items():
        print(f"  {table}:")
        for col in columns:
            print(f"    - {col}")
    print("\n⚠️  BACKUP YOUR DATABASE BEFORE PROCEEDING!")
    print("="*60)
    
    response = input("\nHave you backed up your database? (yes/no): ").strip().lower()
    if response not in ['yes', 'y']:
        print("❌ Cleanup cancelled. Please backup your database first.")
        sys.exit(1)
    
    response = input("Are you sure you want to continue? (yes/no): ").strip().lower()
    if response not in ['yes', 'y']:
        print("❌ Cleanup cancelled.")
        sys.exit(1)

def check_table_exists(engine, table_name: str) -> bool:
    """Check if a table exists in the database"""
    try:
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        return table_name in tables
    except Exception as e:
        logger.error(f"Error checking if table {table_name} exists: {e}")
        return False

def check_column_exists(engine, table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table"""
    try:
        inspector = inspect(engine)
        if not check_table_exists(engine, table_name):
            return False
        
        columns = inspector.get_columns(table_name)
        column_names = [col['name'] for col in columns]
        return column_name in column_names
    except Exception as e:
        logger.error(f"Error checking if column {table_name}.{column_name} exists: {e}")
        return False

def drop_service_tables(engine):
    """Drop service-related tables"""
    logger.info("🗑️  Removing service-based tables...")
    
    dropped_tables = []
    skipped_tables = []
    
    with engine.begin() as conn:
        for table_name in SERVICE_TABLES_TO_REMOVE:
            try:
                if check_table_exists(engine, table_name):
                    # Drop foreign key constraints first (if any)
                    logger.info(f"Dropping table: {table_name}")
                    conn.execute(text(f"DROP TABLE IF EXISTS {table_name} CASCADE;"))
                    dropped_tables.append(table_name)
                    logger.info(f"✅ Dropped table: {table_name}")
                else:
                    skipped_tables.append(table_name)
                    logger.info(f"⏭️  Table {table_name} doesn't exist, skipping")
                    
            except SQLAlchemyError as e:
                logger.error(f"❌ Failed to drop table {table_name}: {e}")
    
    logger.info(f"📊 Tables dropped: {len(dropped_tables)}, skipped: {len(skipped_tables)}")
    if dropped_tables:
        logger.info(f"Dropped tables: {', '.join(dropped_tables)}")

def remove_service_columns(engine):
    """Remove service-related columns from existing tables"""
    logger.info("🗑️  Removing service-related columns...")
    
    removed_columns = []
    skipped_columns = []
    
    with engine.begin() as conn:
        for table_name, columns in COLUMNS_TO_REMOVE.items():
            if not check_table_exists(engine, table_name):
                logger.info(f"⏭️  Table {table_name} doesn't exist, skipping column removal")
                continue
            
            for column_name in columns:
                try:
                    if check_column_exists(engine, table_name, column_name):
                        logger.info(f"Dropping column: {table_name}.{column_name}")
                        conn.execute(text(f"ALTER TABLE {table_name} DROP COLUMN IF EXISTS {column_name};"))
                        removed_columns.append(f"{table_name}.{column_name}")
                        logger.info(f"✅ Dropped column: {table_name}.{column_name}")
                    else:
                        skipped_columns.append(f"{table_name}.{column_name}")
                        logger.info(f"⏭️  Column {table_name}.{column_name} doesn't exist, skipping")
                        
                except SQLAlchemyError as e:
                    logger.error(f"❌ Failed to drop column {table_name}.{column_name}: {e}")
    
    logger.info(f"📊 Columns removed: {len(removed_columns)}, skipped: {len(skipped_columns)}")
    if removed_columns:
        logger.info(f"Removed columns: {', '.join(removed_columns)}")

def clean_asset_data(engine):
    """Clean up asset data by removing service references"""
    logger.info("🧹 Cleaning asset data...")
    
    try:
        with engine.begin() as conn:
            # Remove any service-related data from assets table if columns exist
            if check_column_exists(engine, 'assets', 'service_instance_id'):
                conn.execute(text("UPDATE assets SET service_instance_id = NULL;"))
                logger.info("✅ Cleared service_instance_id references from assets")
            
            # Clean up any JSON fields that might contain service references
            if check_column_exists(engine, 'assets', 'metadata'):
                conn.execute(text("""
                    UPDATE assets 
                    SET metadata = metadata - 'service_mappings' - 'service_correlations'
                    WHERE metadata IS NOT NULL;
                """))
                logger.info("✅ Cleaned service references from asset metadata")
            
            logger.info("✅ Asset data cleanup completed")
            
    except SQLAlchemyError as e:
        logger.error(f"❌ Failed to clean asset data: {e}")

def clean_cve_data(engine):
    """Clean up CVE data by removing service correlations"""
    logger.info("🧹 Cleaning CVE data...")
    
    try:
        with engine.begin() as conn:
            # Reset correlation confidence for asset-based recalculation
            if check_column_exists(engine, 'cves', 'correlation_confidence'):
                conn.execute(text("UPDATE cves SET correlation_confidence = 0.0;"))
                logger.info("✅ Reset CVE correlation confidence scores")
            
            # Clear service-based correlation methods
            if check_column_exists(engine, 'cves', 'correlation_method'):
                conn.execute(text("""
                    UPDATE cves 
                    SET correlation_method = NULL 
                    WHERE correlation_method LIKE '%service%';
                """))
                logger.info("✅ Cleared service-based correlation methods")
            
            logger.info("✅ CVE data cleanup completed")
            
    except SQLAlchemyError as e:
        logger.error(f"❌ Failed to clean CVE data: {e}")

def update_database_schema_version(engine):
    """Update any schema version tracking"""
    logger.info("📝 Updating schema metadata...")
    
    try:
        with engine.begin() as conn:
            # Create a simple metadata tracking if it doesn't exist
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS schema_metadata (
                    key VARCHAR(255) PRIMARY KEY,
                    value VARCHAR(255),
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            
            # Record the cleanup
            conn.execute(text("""
                INSERT INTO schema_metadata (key, value, updated_at)
                VALUES ('architecture', 'asset_based', CURRENT_TIMESTAMP)
                ON CONFLICT (key) DO UPDATE SET 
                    value = EXCLUDED.value,
                    updated_at = EXCLUDED.updated_at;
            """))
            
            conn.execute(text("""
                INSERT INTO schema_metadata (key, value, updated_at)
                VALUES ('service_cleanup', 'completed', CURRENT_TIMESTAMP)
                ON CONFLICT (key) DO UPDATE SET 
                    value = EXCLUDED.value,
                    updated_at = EXCLUDED.updated_at;
            """))
            
            logger.info("✅ Updated schema metadata")
            
    except SQLAlchemyError as e:
        logger.error(f"❌ Failed to update schema metadata: {e}")

def verify_cleanup(engine):
    """Verify that cleanup was successful"""
    logger.info("🔍 Verifying cleanup...")
    
    remaining_service_tables = []
    remaining_service_columns = []
    
    # Check for remaining service tables
    for table_name in SERVICE_TABLES_TO_REMOVE:
        if check_table_exists(engine, table_name):
            remaining_service_tables.append(table_name)
    
    # Check for remaining service columns
    for table_name, columns in COLUMNS_TO_REMOVE.items():
        if check_table_exists(engine, table_name):
            for column_name in columns:
                if check_column_exists(engine, table_name, column_name):
                    remaining_service_columns.append(f"{table_name}.{column_name}")
    
    if remaining_service_tables:
        logger.warning(f"⚠️  Service tables still exist: {', '.join(remaining_service_tables)}")
    
    if remaining_service_columns:
        logger.warning(f"⚠️  Service columns still exist: {', '.join(remaining_service_columns)}")
    
    if not remaining_service_tables and not remaining_service_columns:
        logger.info("✅ Cleanup verification passed - no service-based artifacts remaining")
        return True
    else:
        logger.warning("⚠️  Cleanup verification found remaining service artifacts")
        return False

def main():
    """Main cleanup function"""
    print("🧹 Database Service Architecture Cleanup")
    print("="*50)
    
    # Show backup reminder and get confirmation
    backup_reminder()
    
    try:
        # Connect to database
        engine = get_database_engine()
        
        logger.info("🚀 Starting database cleanup...")
        
        # Step 1: Drop service tables
        drop_service_tables(engine)
        
        # Step 2: Remove service columns
        remove_service_columns(engine)
        
        # Step 3: Clean asset data
        clean_asset_data(engine)
        
        # Step 4: Clean CVE data
        clean_cve_data(engine)
        
        # Step 5: Update schema metadata
        update_database_schema_version(engine)
        
        # Step 6: Verify cleanup
        success = verify_cleanup(engine)
        
        if success:
            print("\n" + "="*50)
            print("✅ DATABASE CLEANUP COMPLETED SUCCESSFULLY!")
            print("="*50)
            print("Next steps:")
            print("1. Update your application code to remove service imports")
            print("2. Run asset-focused CVE collection")
            print("3. Test the application functionality")
            print("4. Set up asset-based CPE correlation")
        else:
            print("\n" + "="*50)
            print("⚠️  CLEANUP COMPLETED WITH WARNINGS")
            print("="*50)
            print("Some service artifacts may still exist.")
            print("Check the logs above for details.")
        
    except Exception as e:
        logger.error(f"💥 Cleanup failed: {e}")
        print("\n" + "="*50)
        print("❌ CLEANUP FAILED")
        print("="*50)
        print(f"Error: {e}")
        print("Please check the logs and fix any issues before retrying.")
        sys.exit(1)
    
    finally:
        print("\nCleanup script completed.")

if __name__ == "__main__":
    main()