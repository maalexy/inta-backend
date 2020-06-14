"""empty message

Revision ID: 4434247efc72
Revises: 47b4b9602875
Create Date: 2020-06-14 21:42:48.227918

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4434247efc72'
down_revision = '47b4b9602875'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('challenge_file',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('challenge_id', sa.Integer(), nullable=True),
    sa.Column('file', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.add_column('challenge', sa.Column('pos', sa.String(), nullable=True))
    op.add_column('challenge_goal', sa.Column('point', sa.Integer(), nullable=True))
    op.add_column('challenge_goal', sa.Column('pos', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('challenge_goal', 'pos')
    op.drop_column('challenge_goal', 'point')
    op.drop_column('challenge', 'pos')
    op.drop_table('challenge_file')
    # ### end Alembic commands ###
