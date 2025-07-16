from typing import TypedDict
from agents.rag.document_converter import convert_event_to_text

class State(TypedDict):
    event: dict
    event_summary: str

def summarize_event(state: State) -> State:
    """이벤트를 요약하여 텍스트로 변환합니다."""
    event_summary = convert_event_to_text(state['event'])
    return {
        'event_summary': event_summary,
    } 