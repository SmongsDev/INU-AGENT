from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, DateTime, UUID
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.dialects.postgresql import JSONB, INET, TIMESTAMP
from datetime import datetime
import uuid

Base = declarative_base()

class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    users = relationship("User", back_populates="group")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    role = Column(String, nullable=False)
    group_id = Column(Integer, ForeignKey("groups.id"))

    group = relationship("Group", back_populates="users")

class CloudTrail(Base):
    __tablename__ = "cloudtrail"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(String)
    created_at = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    event_version = Column(String)
    event_time = Column(TIMESTAMP(timezone=True))
    event_source = Column(String)
    event_name = Column(String)
    event_category = Column(String)
    event_type = Column(String)
    aws_region = Column(String)
    read_only = Column(Boolean)
    request_id = Column(String)
    source_ip = Column(INET)
    user_agent = Column(String)
    management_event = Column(Boolean)
    recipient_account_id = Column(String)
    session_credential_from_console = Column(String)
    shared_event_id = Column(String)
    error_code = Column(String)
    error_message = Column(String)
    user_identity = Column(JSONB)
    tls_details = Column(JSONB)
    request_parameters = Column(JSONB)
    response_elements = Column(JSONB)
    insight_details = Column(JSONB)
    resources = Column(JSONB)
    is_false_positive = Column(Boolean, default=False)