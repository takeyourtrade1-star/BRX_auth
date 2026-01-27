"""Initial schema

Revision ID: 001_initial
Revises: 
Create Date: 2026-01-27 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create extensions
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
    
    # Create enums
    account_status_enum = postgresql.ENUM(
        'active', 'locked', 'banned', 'pending_verification',
        name='account_status_enum',
        create_type=True
    )
    account_status_enum.create(op.get_bind(), checkfirst=True)
    
    event_type_enum = postgresql.ENUM(
        'LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT', 'PASSWORD_CHANGE',
        'MFA_enabled', 'MFA_FAILED', 'SUSPICIOUS_ACTIVITY', 'ACCOUNT_LOCKED',
        name='event_type_enum',
        create_type=True
    )
    event_type_enum.create(op.get_bind(), checkfirst=True)
    
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('security_stamp', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('mfa_secret_enc', sa.Text(), nullable=True),
        sa.Column('account_status', account_status_enum, nullable=False, server_default='pending_verification'),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('locked_until', sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )
    op.create_index('idx_users_email', 'users', ['email'])
    
    # Create sessions table
    op.create_table(
        'sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('refresh_token_hash', sa.String(64), nullable=False),
        sa.Column('device_fingerprint', sa.String(255), nullable=True),
        sa.Column('ip_address', postgresql.INET(), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('expires_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('is_revoked', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('revoked_at', sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('revoked_reason', sa.String(255), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('refresh_token_hash')
    )
    op.create_index('idx_sessions_token_hash', 'sessions', ['refresh_token_hash'])
    op.create_index('idx_sessions_user_id', 'sessions', ['user_id'])
    
    # Create security_audit_logs table
    op.create_table(
        'security_audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('event_type', event_type_enum, nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('ip_address', postgresql.INET(), nullable=False),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('geo_location', postgresql.JSONB(), nullable=True),
        sa.Column('metadata', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_audit_created_at', 'security_audit_logs', ['created_at'])
    op.create_index('idx_audit_ip_address', 'security_audit_logs', ['ip_address'])


def downgrade() -> None:
    op.drop_index('idx_audit_ip_address', table_name='security_audit_logs')
    op.drop_index('idx_audit_created_at', table_name='security_audit_logs')
    op.drop_table('security_audit_logs')
    op.drop_index('idx_sessions_user_id', table_name='sessions')
    op.drop_index('idx_sessions_token_hash', table_name='sessions')
    op.drop_table('sessions')
    op.drop_index('idx_users_email', table_name='users')
    op.drop_table('users')
    
    # Drop enums
    op.execute('DROP TYPE IF EXISTS event_type_enum')
    op.execute('DROP TYPE IF EXISTS account_status_enum')
