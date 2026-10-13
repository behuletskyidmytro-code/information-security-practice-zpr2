"""ZPR2 encrypted PII and audit"""
from alembic import op
import sqlalchemy as sa
revision='2f20a0b0c0d0'
down_revision='9d24a4587bf9'
branch_labels=None
depends_on=None

def upgrade():
    with op.batch_alter_table('users') as batch:
        batch.add_column(sa.Column('encrypted_email',sa.String(500),nullable=True))
        batch.add_column(sa.Column('email_index',sa.String(64),nullable=True))
        batch.add_column(sa.Column('encrypted_phone',sa.String(500),nullable=True))
        batch.add_column(sa.Column('full_name',sa.String(150),nullable=True))
        batch.create_index('ix_users_email_index',['email_index'],unique=True)
    op.create_table('audit_log',sa.Column('id',sa.Integer,primary_key=True),sa.Column('user_id',sa.Integer),sa.Column('username',sa.String(50)),sa.Column('ip_address',sa.String(45),nullable=False),sa.Column('action',sa.String(50),nullable=False),sa.Column('resource',sa.String(100)),sa.Column('timestamp',sa.DateTime,nullable=False),sa.Column('http_method',sa.String(10)),sa.Column('endpoint',sa.String(200)),sa.Column('status',sa.String(20),nullable=False),sa.Column('status_code',sa.Integer),sa.Column('details',sa.Text))
    op.create_index('ix_audit_log_timestamp','audit_log',['timestamp'])
    op.create_index('ix_audit_action_ts','audit_log',['action','timestamp'])
    op.create_index('ix_audit_ip_action','audit_log',['ip_address','action'])

def downgrade():
    op.drop_table('audit_log')
    with op.batch_alter_table('users') as batch:
        batch.drop_index('ix_users_email_index')
        for col in ('encrypted_email','email_index','encrypted_phone','full_name'):batch.drop_column(col)
