from sqlalchemy import (
    Column, Integer, String, ForeignKey,
    Boolean, Enum, TIMESTAMP, Float
)
from sqlalchemy.dialects.postgresql import UUID as PgUUID, INET, JSONB
from pgvector.sqlalchemy import Vector
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import uuid
from app.schemas.base import RoleType, NotifFreq, NotifChannel, SourceProduct

Base = declarative_base()

class Group(Base):
    __tablename__ = "groups"

    id = Column(PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    name = Column(String, nullable=False, comment="회사 이름")
    code = Column(String, nullable=False, comment="회사 코드")
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.now)

    # Relationships
    users = relationship("User", back_populates="group")
    settings = relationship("Settings", back_populates="group", uselist=False)
    meta_data = relationship("Meta_Data", back_populates="group", uselist=False)
    events = relationship("Event", back_populates="group")
    aas = relationship("aas", back_populates="group")

class Settings(Base):
    __tablename__ = "settings"

    group_id = Column(PgUUID(as_uuid=True), ForeignKey("groups.id"), primary_key=True, unique=True)
    notif_email = Column(String)
    notif_enabled = Column(Boolean, nullable=False, default=False)
    notif_channel = Column(Enum(NotifChannel))
    notif_freq = Column(Enum(NotifFreq), nullable=False, default=NotifFreq.realtime)

    # Relationships
    group = relationship("Group", back_populates="settings")

class Meta_Data(Base):
    __tablename__ = "meta_data"

    group_id = Column(PgUUID(as_uuid=True), ForeignKey("groups.id"), primary_key=True, unique=True)
    data_sync_time = Column(TIMESTAMP, nullable=False, default=datetime.now)
    agent_flow = Column(JSONB)

    # Relationships
    group = relationship("Group", back_populates="meta_data")

class User(Base):
    __tablename__ = "users"

    id = Column(PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    group_id = Column(PgUUID(as_uuid=True), ForeignKey("groups.id"), nullable=False)
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

    id = Column(PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    user_id = Column(PgUUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    ip_addr = Column(INET, nullable=False)
    refresh_token = Column(String, nullable=False, comment="JWT Refresh Token")
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.now)
    expired_at = Column(TIMESTAMP)

    # Relationships
    user = relationship("User", back_populates="sessions")

class Event(Base):
    __tablename__ = "events"

    id = Column(PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id = Column(PgUUID(as_uuid=True), ForeignKey("groups.id"), nullable=False)
    source_product = Column(Enum(SourceProduct), nullable=False)
    source_ip = Column(INET)
    user_agent = Column(String)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=datetime.now)

    # Relationships
    group = relationship("Group", back_populates="events")
    ml_logs = relationship("MLLog", back_populates="event")
    cloudtrails = relationship("CloudTrail", back_populates="event")
    cloudwatches = relationship("CloudWatch", back_populates="event")
    documents = relationship("Document", back_populates="event")

class CloudTrail(Base):
    __tablename__ = "cloudtrail"

    id = Column(PgUUID(as_uuid=True), ForeignKey("events.id"), primary_key=True)
    event_id = Column(PgUUID(as_uuid=True), nullable=False)
    event_version = Column(String, nullable=False)
    event_time = Column(TIMESTAMP(timezone=True), nullable=False)
    event_source = Column(String, nullable=False)
    event_name = Column(String, nullable=False)
    event_category = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    aws_region = Column(String, nullable=False)
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

    # Relationships
    event = relationship("Event", back_populates="cloudtrails")

class CloudWatch(Base):
    __tablename__ = "cloudwatch"

    id = Column(PgUUID(as_uuid=True), ForeignKey("events.id"), primary_key=True)
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

    # Relationships
    event = relationship("Event", back_populates="cloudwatches")

class MLLog(Base):
    __tablename__ = "ml_log"

    id = Column(PgUUID(as_uuid=True), ForeignKey("events.id"), primary_key=True)
    event_id   = Column(PgUUID(as_uuid=True), nullable=False)
    severity   = Column(Integer)
    confidence = Column(Float)

    # Relationships
    event = relationship("Event", back_populates="ml_logs")
    false_positive_logs = relationship("FalsePositiveLog", back_populates="ml_log")
    filter_logs = relationship("FilterLog", back_populates="ml_log")

class FalsePositiveLog(Base):
    __tablename__ = "false_positive_log"

    id         = Column(PgUUID(as_uuid=True), ForeignKey("ml_log.id"), primary_key=True)
    severity   = Column(Integer)
    confidence = Column(Float)
    reason     = Column(String)
    result     = Column(JSONB)

    # Relationships
    ml_log = relationship("MLLog", back_populates="false_positive_logs")

class FilterLog(Base):
    __tablename__ = "filter_log"

    id        = Column(PgUUID(as_uuid=True), ForeignKey("ml_log.id"), primary_key=True)
    result    = Column(JSONB)

    # Relationships
    ml_log = relationship("MLLog", back_populates="filter_logs")

class Document(Base):
    __tablename__ = "document"

    id = Column(PgUUID(as_uuid=True), ForeignKey("events.id"), primary_key=True)
    content       = Column(String)
    metadata_json = Column(JSONB)
    embedding     = Column(Vector)

    # Relationships
    event = relationship("Event", back_populates="documents")

# service
class aas(Base):
    __tablename__ = "aas"

    id = Column(Integer, primary_key=True, autoincrement=True)
    group_id = Column(PgUUID(as_uuid=True), ForeignKey("groups.id"), nullable=False)
    flow_name = Column(String)
    flow_json = Column(JSONB)
    thumbnail_s3_key = Column(String, nullable=True)

    # Relationships
    group = relationship("Group", back_populates="aas")

class Dashboard(Base):
    __tablename__ = "dashboard"

    id = Column(Integer, primary_key=True, autoincrement=True)
    group_id = Column(PgUUID(as_uuid=True), ForeignKey("groups.id"), nullable=False)
    dashboard = Column(JSONB, nullable=False)
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.now)

    # Relationships
    group = relationship("Group")

# view
class VwEventsEnriched(Base):
    __tablename__  = "vw_events_enriched"
    __table_args__ = {"info": {"is_view": True}}

    id             = Column(PgUUID(as_uuid=True), primary_key=True)
    group_id       = Column(PgUUID(as_uuid=True), nullable=False)
    source_product = Column(Enum(SourceProduct), nullable=False)
    source_ip      = Column(INET)
    user_agent     = Column(String)
    created_at     = Column(TIMESTAMP(timezone=True), nullable=False)
    severity       = Column(Integer)
    confidence     = Column(Float)
    result         = Column(JSONB)
    alert_key      = Column(String)


