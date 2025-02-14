"""Add input/output hex and text fields to History model

Revision ID: 58aa40797d94
Revises: 034d6e36486f
Create Date: 2024-11-29 02:00:21.735844

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '58aa40797d94'
down_revision = '034d6e36486f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('history', schema=None) as batch_op:
        batch_op.add_column(sa.Column('input_hex', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('input_text', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('output_hex', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('output_text', sa.Text(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('history', schema=None) as batch_op:
        batch_op.drop_column('output_text')
        batch_op.drop_column('output_hex')
        batch_op.drop_column('input_text')
        batch_op.drop_column('input_hex')

    # ### end Alembic commands ###
