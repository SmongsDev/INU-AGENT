from typing import TypedDict
from app.schemas.cloudtrail import CloudTrailEvent
from agent.nodes.rag.document_converter import convert_cloudtrail_to_text

class State(TypedDict):
    event: CloudTrailEvent
    event_summary: str

def summarize_event(state: State) -> State:
    """이벤트를 요약하여 텍스트로 변환합니다."""
    event_summary = convert_cloudtrail_to_text(state['event'])
    return {
        'event_summary': event_summary,
    } 