import pytest
from app.services.cloudtrail_service import CloudTrailService

@pytest.fixture
def service():
    return CloudTrailService(group_id="accbe9c0-7ae8-4aa3-a0c7-9992e009f8cf")

def test_build_actor_key_with_arn(service):
    # ARN이 직접 제공된 경우
    user_identity = {
        "arn": "arn:aws:iam::123456789012:user/test-user"
    }
    assert service._build_actor_key(user_identity) == "arn:aws:iam::123456789012:user/test-user"

def test_build_actor_key_with_session_issuer(service):
    # 세션 컨텍스트의 발급자 ARN이 있는 경우
    user_identity = {
        "sessionContext": {
            "sessionIssuer": {
                "arn": "arn:aws:iam::123456789012:role/test-role"
            }
        }
    }
    assert service._build_actor_key(user_identity) == "arn:aws:iam::123456789012:role/test-role"

def test_build_actor_key_with_username_and_account(service):
    # IAM 사용자 이름과 계정 ID가 있는 경우
    user_identity = {
        "userName": "test-user",
        "accountId": "123456789012"
    }
    assert service._build_actor_key(user_identity) == "arn:aws:iam::123456789012:user/test-user"

def test_build_actor_key_with_principal_id(service):
    # Principal ID가 있는 경우
    user_identity = {
        "principalId": "AROAXXXXXXXXXXXXXXXXX"
    }
    assert service._build_actor_key(user_identity) == "AROAXXXXXXXXXXXXXXXXX"

def test_build_actor_key_with_access_key(service):
    # Access Key ID가 있는 경우
    user_identity = {
        "accessKeyId": "AKIAXXXXXXXXXXXXXXXX"
    }
    assert service._build_actor_key(user_identity) == "ACCESS_KEY:AKIAXXXXXXXXXXXXXXXX"

def test_build_actor_key_with_identity_provider(service):
    # 외부 인증 제공자 정보가 있는 경우
    user_identity = {
        "identityProvider": "SAML",
        "credentialId": "test-credential"
    }
    assert service._build_actor_key(user_identity) == "SAML:test-credential"

def test_build_actor_key_with_request_parameters(service):
    # 요청 파라미터에 userArn이 있는 경우
    user_identity = {}
    request_parameters = {
        "userArn": "arn:aws:iam::123456789012:user/test-user"
    }
    assert service._build_actor_key(user_identity, request_parameters) == "arn:aws:iam::123456789012:user/test-user"

def test_build_actor_key_with_account_id_only(service):
    # 계정 ID만 있는 경우
    user_identity = {
        "accountId": "123456789012"
    }
    assert service._build_actor_key(user_identity) == "AWS_ACCOUNT:123456789012"

def test_build_actor_key_with_empty_identity(service):
    # 빈 user_identity가 제공된 경우
    assert service._build_actor_key({}) is None

def test_build_actor_key_with_none_identity(service):
    # user_identity가 None인 경우
    assert service._build_actor_key(None) is None

def test_build_actor_key_priority(service):
    """우선순위 테스트: 여러 식별자가 있을 때 우선순위가 높은 것이 선택되는지 확인"""
    user_identity = {
        "arn": "arn:aws:iam::123456789012:user/high-priority",
        "userName": "low-priority-user",
        "accountId": "123456789012",
        "principalId": "low-priority-principal",
        "accessKeyId": "low-priority-key"
    }
    # ARN이 가장 높은 우선순위를 가지므로 이것이 반환되어야 함
    assert service._build_actor_key(user_identity) == "arn:aws:iam::123456789012:user/high-priority"
