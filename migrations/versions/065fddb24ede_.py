"""empty message

Revision ID: 065fddb24ede
Revises: 76dd446dfa10
Create Date: 2020-05-02 17:27:55.751592

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '065fddb24ede'
down_revision = '76dd446dfa10'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('challange',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(), nullable=True),
    sa.Column('text', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('challange_goal',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('challange_id', sa.Integer(), nullable=True),
    sa.Column('text', sa.String(), nullable=True),
    sa.Column('category', sa.String(), nullable=True),
    sa.Column('required', sa.Boolean(), nullable=True),
    sa.Column('position', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('challange_goal')
    op.drop_table('challange')
    # ### end Alembic commands ###