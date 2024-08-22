"""Descripción de los cambios

Revision ID: 5dcef1bcb2bd
Revises: 
Create Date: 2024-08-10 23:27:25.540053

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5dcef1bcb2bd'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Verificar si la columna 'parent_id' ya existe
    existing_columns = sa.inspect(op.get_bind()).get_columns('comment')
    if 'parent_id' not in [column['name'] for column in existing_columns]:
        with op.batch_alter_table('comment', schema=None) as batch_op:
            batch_op.add_column(sa.Column('parent_id', sa.Integer(), nullable=True))
            batch_op.create_foreign_key('fk_comment_parent_id', 'comment', ['parent_id'], ['id'])

def downgrade():
    with op.batch_alter_table('comment', schema=None) as batch_op:
        batch_op.drop_constraint('fk_comment_parent_id', type_='foreignkey')
        batch_op.drop_column('parent_id')


