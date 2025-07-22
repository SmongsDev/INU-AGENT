import json
import dotenv
from pathlib import Path
from langgraph_flow.graph import process_security_event

# 테스트 시작 전에 환경 변수 로드
dotenv.load_dotenv()

def load_sample_event():
    """테스트용 샘플 이벤트를 로드합니다."""
    sample_path = Path(__file__).parent / "data" / "sample_event.json"
    with open(sample_path, "r") as f:
        return json.load(f)

def test_process_security_event():
    """정오탐 탐지 프로세스를 테스트합니다."""
    # Given
    event = load_sample_event()
    # When
    result = process_security_event(event)
    # Then
    assert isinstance(result, dict)
    assert "is_false_positive" in result
    assert isinstance(result["is_false_positive"], bool)
    assert "explanation" in result
    assert isinstance(result["explanation"], str)

