"""empty message

Revision ID: 4daa1b3ababd
Revises: 
Create Date: 2024-08-24 11:48:05.028392

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4daa1b3ababd'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('product_image',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('image_url', sa.String(length=200), nullable=False),
    sa.Column('product_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['product_id'], ['product.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('product', schema=None) as batch_op:
        batch_op.add_column(sa.Column('recommendations', sa.Text(), nullable=True))
        batch_op.drop_column('image_url')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('product', schema=None) as batch_op:
        batch_op.add_column(sa.Column('image_url', sa.VARCHAR(length=200), nullable=False))
        batch_op.drop_column('recommendations')

    op.drop_table('product_image')
    # ### end Alembic commands ###
