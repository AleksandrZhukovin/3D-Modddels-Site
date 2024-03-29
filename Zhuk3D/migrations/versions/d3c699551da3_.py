"""empty message

Revision ID: d3c699551da3
Revises: 330c50cb4916
Create Date: 2021-05-04 20:28:20.266543

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd3c699551da3'
down_revision = '330c50cb4916'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('item', sa.Column('path_10', sa.String(), nullable=True))
    op.add_column('item', sa.Column('path_6', sa.String(), nullable=True))
    op.add_column('item', sa.Column('path_7', sa.String(), nullable=True))
    op.add_column('item', sa.Column('path_8', sa.String(), nullable=True))
    op.add_column('item', sa.Column('path_9', sa.String(), nullable=True))
    op.drop_index('ix_post_tags', table_name='item')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_index('ix_post_tags', 'item', ['description'], unique=False)
    op.drop_column('item', 'path_9')
    op.drop_column('item', 'path_8')
    op.drop_column('item', 'path_7')
    op.drop_column('item', 'path_6')
    op.drop_column('item', 'path_10')
    # ### end Alembic commands ###
