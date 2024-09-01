"""Add date_created to User model

Revision ID: 90ad849b2eed
Revises: 19ebede60e3e
Create Date: 2024-08-31 19:35:47.666928

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '90ad849b2eed'
down_revision = '19ebede60e3e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('date_created', sa.DateTime(), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('date_created')

    # ### end Alembic commands ###