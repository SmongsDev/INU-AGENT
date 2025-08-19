import uuid
from datetime import datetime
from app.db.models import Group, User, Session, Event, CloudTrail
from app.schemas.base import RoleType, SourceProduct

def test_create_group(db_session):
    """Group 생성 테스트"""
    group = Group(
        name="테스트 회사",
        created_at=datetime.now()
    )
    db_session.add(group)
    db_session.commit()

    saved_group = db_session.query(Group).filter_by(name="테스트 회사").first()
    assert saved_group is not None
    assert saved_group.name == "테스트 회사"

def test_create_user_with_group(db_session):
    """User와 Group 관계 테스트"""
    # 그룹 생성
    group = Group(
        name="테스트 회사",
        created_at=datetime.now()
    )
    db_session.add(group)
    db_session.flush()

    # 사용자 생성
    user = User(
        group_id=group.id,
        name="테스트 사용자",
        email="test@example.com",
        pw_hash="hashed_password",
        role=RoleType.administrator,
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    db_session.add(user)
    db_session.commit()

    # 검증
    saved_user = db_session.query(User).filter_by(email="test@example.com").first()
    assert saved_user is not None
    assert saved_user.name == "테스트 사용자"
    assert saved_user.group.name == "테스트 회사"

def test_create_event_with_cloudtrail(db_session):
    """Event와 CloudTrail 1:1 관계 테스트"""
    # 그룹 생성
    group = Group(
        name="테스트 회사",
        created_at=datetime.now()
    )
    db_session.add(group)
    db_session.flush()

    # 이벤트 생성
    event = Event(
        group_id=group.id,
        source_product=SourceProduct.cloudtrail,
        created_at=datetime.now()
    )
    db_session.add(event)
    db_session.flush()

    # CloudTrail 생성
    cloudtrail = CloudTrail(
        id=event.id,  # 1:1 관계를 위해 동일한 ID 사용
        event_id=str(uuid.uuid4()),
        event_version="1.0",
        event_time=datetime.now(),
        event_source="aws.test",
        event_name="TestEvent",
        event_category="Test",
        event_type="AwsApiCall",
        aws_region="ap-northeast-2",
        user_identity={"type": "IAMUser"},
        request_parameters={},
        response_elements={}
    )
    db_session.add(cloudtrail)
    db_session.commit()

    # 검증
    saved_event = db_session.query(Event).filter_by(id=event.id).first()
    assert saved_event is not None
    assert saved_event.cloudtrails is not None
    assert saved_event.cloudtrails[0].event_name == "TestEvent"

def test_create_user_session(db_session):
    """User와 Session 관계 테스트"""
    # 그룹 생성
    group = Group(
        name="테스트 회사",
        created_at=datetime.now()
    )
    db_session.add(group)
    db_session.flush()

    # 사용자 생성
    user = User(
        group_id=group.id,
        name="테스트 사용자",
        email="test@example.com",
        pw_hash="hashed_password",
        role=RoleType.administrator,
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    db_session.add(user)
    db_session.flush()

    # 세션 생성
    session = Session(
        user_id=user.id,
        ip_addr="192.168.1.1",
        token="test_token",
        created_at=datetime.now()
    )
    db_session.add(session)
    db_session.commit()

    # 검증
    saved_session = db_session.query(Session).filter_by(token="test_token").first()
    assert saved_session is not None
    assert saved_session.user.email == "test@example.com"
