"""add_enhanced_cve_fields_manual

Revision ID: 748ccc6342f1
Revises: c946d781d602
Create Date: 2025-08-22 03:03:18.465025

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import reflection

# revision identifiers, used by Alembic.
revision: str = '1e1d1e5c8df2'
down_revision: Union[str, None] = 'b21da46fe919'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def column_exists(table_name, column_name):
    """Check if a column exists in a table"""
    bind = op.get_bind()
    inspector = reflection.Inspector.from_engine(bind)
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns


def index_exists(index_name):
    """Check if an index exists"""
    bind = op.get_bind()
    inspector = reflection.Inspector.from_engine(bind)
    # Get all indexes from all tables
    for table_name in inspector.get_table_names():
        indexes = [idx['name'] for idx in inspector.get_indexes(table_name)]
        if index_name in indexes:
            return True
    return False


def upgrade() -> None:
    # Add enhanced fields to CVE table
    # if not column_exists('cves', 'affected_products'):
    #     op.add_column('cves', sa.Column('affected_products', sa.JSON(), nullable=True))
        
    # if not column_exists('cves', 'cpe_entries'):
    #     op.add_column('cves', sa.Column('cpe_entries', sa.JSON(), nullable=True))
        
    # if not column_exists('cves', 'correlation_confidence'):
    #     op.add_column('cves', sa.Column('correlation_confidence', sa.Float(), nullable=True))
        
    # if not column_exists('cves', 'correlation_method'):
    #     op.add_column('cves', sa.Column('correlation_method', sa.String(50), nullable=True))
        
    # if not column_exists('cves', 'affects_service_types'):
    #     op.add_column('cves', sa.Column('affects_service_types', sa.JSON(), nullable=True))
    
    # # Add enhanced fields to service_types table
    # if not column_exists('service_types', 'product_name'):
    #     op.add_column('service_types', sa.Column('product_name', sa.String(200), nullable=True))
        
    # if not column_exists('service_types', 'vendor_aliases'):
    #     op.add_column('service_types', sa.Column('vendor_aliases', sa.JSON(), nullable=True))
        
    # if not column_exists('service_types', 'product_aliases'):
    #     op.add_column('service_types', sa.Column('product_aliases', sa.JSON(), nullable=True))
    
    # # Create indexes
    # if not index_exists('idx_cves_correlation_confidence'):
    #     op.create_index('idx_cves_correlation_confidence', 'cves', ['correlation_confidence'])
        
    # if not index_exists('idx_service_types_product_name'):
    #     op.create_index('idx_service_types_product_name', 'service_types', ['product_name'])
    pass


def downgrade() -> None:
    # Drop indexes if they exist
    if index_exists('idx_service_types_product_name'):
        op.drop_index('idx_service_types_product_name')
        
    if index_exists('idx_cves_correlation_confidence'):
        op.drop_index('idx_cves_correlation_confidence')
    
    # Drop columns if they exist
    if column_exists('service_types', 'product_aliases'):
        op.drop_column('service_types', 'product_aliases')
        
    if column_exists('service_types', 'vendor_aliases'):
        op.drop_column('service_types', 'vendor_aliases')
        
    if column_exists('service_types', 'product_name'):
        op.drop_column('service_types', 'product_name')
        
    if column_exists('cves', 'affects_service_types'):
        op.drop_column('cves', 'affects_service_types')
        
    if column_exists('cves', 'correlation_method'):
        op.drop_column('cves', 'correlation_method')
        
    if column_exists('cves', 'correlation_confidence'):
        op.drop_column('cves', 'correlation_confidence')
        
    if column_exists('cves', 'cpe_entries'):
        op.drop_column('cves', 'cpe_entries')
        
    if column_exists('cves', 'affected_products'):
        op.drop_column('cves', 'affected_products')
