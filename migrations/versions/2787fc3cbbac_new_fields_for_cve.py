"""New Fields for CVE

Revision ID: 2787fc3cbbac
Revises: 94cfb91c1670
Create Date: 2025-08-21 19:42:23.023852

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2787fc3cbbac'
down_revision: Union[str, None] = '94cfb91c1670'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
