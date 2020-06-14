"""empty message

Revision ID: 9cd711bbe9f4
Revises: 065fddb24ede
Create Date: 2020-05-21 21:42:59.173757

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9cd711bbe9f4'
down_revision = '065fddb24ede'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('challenge',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(), nullable=True),
    sa.Column('text', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('challenge_goal',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('challenge_id', sa.Integer(), nullable=True),
    sa.Column('text', sa.String(), nullable=True),
    sa.Column('category', sa.String(), nullable=True),
    sa.Column('required', sa.Boolean(), nullable=True),
    sa.Column('position', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('challange_goal')
    op.drop_table('challange')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('challange',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('title', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.Column('text', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='challange_pkey')
    )
    op.create_table('challange_goal',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('challange_id', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('text', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.Column('category', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.Column('required', sa.BOOLEAN(), autoincrement=False, nullable=True),
    sa.Column('position', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='challange_goal_pkey')
    )
    op.drop_table('challenge_goal')
    op.drop_table('challenge')
    # ### end Alembic commands ###