from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, ForeignKey, Table, DateTime, Text, Index
from sqlalchemy.orm import relationship
from app.database import Base
from app.crypto.encryption import encrypt_field, decrypt_field, blind_index

user_roles = Table('user_roles', Base.metadata, Column('user_id', Integer, ForeignKey('users.id'), primary_key=True), Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True))
role_permissions = Table('role_permissions', Base.metadata, Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True), Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True))

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    encrypted_email = Column(String(500), nullable=True)
    email_index = Column(String(64), unique=True, nullable=True, index=True)
    encrypted_phone = Column(String(500), nullable=True)
    full_name = Column(String(150), nullable=True)
    roles = relationship('Role', secondary=user_roles, back_populates='users')
    @property
    def email(self): return decrypt_field(self.encrypted_email)
    @email.setter
    def email(self, value):
        self.encrypted_email = encrypt_field(value)
        self.email_index = blind_index(value) if value else None
    @property
    def phone(self): return decrypt_field(self.encrypted_phone)
    @phone.setter
    def phone(self, value): self.encrypted_phone = encrypt_field(value)

class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    users = relationship('User', secondary=user_roles, back_populates='roles')
    permissions = relationship('Permission', secondary=role_permissions, back_populates='roles')

class Permission(Base):
    __tablename__ = 'permissions'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    roles = relationship('Role', secondary=role_permissions, back_populates='permissions')

class AuditLog(Base):
    __tablename__ = 'audit_log'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String(50), nullable=True)
    ip_address = Column(String(45), nullable=False)
    action = Column(String(50), nullable=False)
    resource = Column(String(100), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    http_method = Column(String(10), nullable=True)
    endpoint = Column(String(200), nullable=True)
    status = Column(String(20), nullable=False)
    status_code = Column(Integer, nullable=True)
    details = Column(Text, nullable=True)
    __table_args__ = (Index('ix_audit_action_ts','action','timestamp'),Index('ix_audit_ip_action','ip_address','action'))
