from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, DateTime, Enum, TIMESTAMP, JSON, Float
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB, VECTOR
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import uuid
from app.schemas.base import RoleType, NotifFreq, NotifChannel, SourceProduct

Base = declarative_base()

class Group(Base):
    __tablename__ = "groups"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    name = Column(String, nullable=False, comment="회사 이름")
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.now)

    # Relationships
    users = relationship("User", back_populates="group")
    settings = relationship("Settings", back_populates="group", uselist=False)
    metadata = relationship("Metadata", back_populates="group", uselist=False)
    events = relationship("Event", back_populates="group")

class User(Base):
    __tablename__ = "user"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    group_id = Column(UUID(as_uuid=True), ForeignKey("groups.id"), nullable=False)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    pw_hash = Column(String, nullable=False, comment="bcrypt")
    role = Column(Enum(RoleType), nullable=False)
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.now)
    updated_at = Column(TIMESTAMP, nullable=False, default=datetime.now)

    # Relationships
    group = relationship("Group", back_populates="users")
    sessions = relationship("Session", back_populates="user")

class Session(Base):
    __tablename__ = "session"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("user.id"), nullable=False)
    ip_addr = Column(INET, nullable=False)
    token = Column(String, nullable=False)
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.now)
    expired_at = Column(TIMESTAMP)

    # Relationships
    user = relationship("User", back_populates="sessions")

class CloudWatch(Base):
    __tablename__ = "cloudwatch"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_version = Column(String, nullable=False)
    event_time = Column(TIMESTAMP(timezone=True), nullable=False)
    event_source = Column(String, nullable=False)
    event_name = Column(String, nullable=False)
    aws_region = Column(String, nullable=False)
    source_ip_address = Column(INET)
    user_agent = Column(String)
    userIdentity = Column(JSONB)
    request_parameters = Column(JSONB)
    response_elements = Column(JSONB)
    created_at = Column(TIMESTAMP(timezone=True), default=datetime.now)

class Settings(Base):
    __tablename__ = "settings"

    group_id = Column(UUID(as_uuid=True), ForeignKey("groups.id"), primary_key=True, unique=True)
    notif_email = Column(String)
    notif_enabled = Column(Boolean, nullable=False, default=False)
    notif_channel = Column(Enum(NotifChannel))
    notif_freq = Column(Enum(NotifFreq), nullable=False, default=NotifFreq.realtime)

    # Relationships
    group = relationship("Group", back_populates="settings")

class Metadata(Base):
    __tablename__ = "metadata"

    group_id = Column(UUID(as_uuid=True), ForeignKey("groups.id"), primary_key=True, unique=True)
    data_sync_time = Column(TIMESTAMP)

    # Relationships
    group = relationship("Group", back_populates="metadata")

class Event(Base):
    __tablename__ = "events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id = Column(UUID(as_uuid=True), ForeignKey("groups.id"), nullable=False)
    source_product = Column(Enum(SourceProduct), nullable=False)
    source_ip = Column(INET)
    user_agent = Column(String)
    payload = Column(JSONB, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=datetime.now)

    # Relationships
    group = relationship("Group", back_populates="events")
    ml_logs = relationship("MLLog", back_populates="event")
    documents = relationship("Document", back_populates="event")

class MLLog(Base):
    __tablename__ = "ml_log"

    id = Column(UUID(as_uuid=True), primary_key=True)
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id"))
    severity = Column(Integer)
    confidence = Column(Float)
    result = Column(JSONB)

    # Relationships
    event = relationship("Event", back_populates="ml_logs")
    false_positive_logs = relationship("FalsePositiveLog", back_populates="ml_log")
    filter_logs = relationship("FilterLog", back_populates="ml_log")

class FalsePositiveLog(Base):
    __tablename__ = "false_positive_log"

    id = Column(UUID(as_uuid=True), primary_key=True)
    ml_id = Column(UUID(as_uuid=True), ForeignKey("ml_log.id"))
    severity = Column(Integer)
    confidence = Column(Float)
    reason = Column(String)
    result = Column(JSONB)

    # Relationships
    ml_log = relationship("MLLog", back_populates="false_positive_logs")

class FilterLog(Base):
    __tablename__ = "filter_log"

    id = Column(UUID(as_uuid=True), primary_key=True)
    ml_id = Column(UUID(as_uuid=True), ForeignKey("ml_log.id"))
    result = Column(JSONB)

    # Relationships
    ml_log = relationship("MLLog", back_populates="filter_logs")

class Document(Base):
    __tablename__ = "document"

    id = Column(UUID(as_uuid=True), primary_key=True)
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id"))
    content = Column(String)
    metadata = Column(JSONB)
    embedding = Column(VECTOR)

    # Relationships
    event = relationship("Event", back_populates="documents")