from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from agent.Analyze_agent.tools.base import store_event

class State(TypedDict):
    messages: Annotated[list, add_messages]
    event: dict
    sql_result: str
    similar_events: list
    is_false_positive: bool
    explanation: str
    confidence: float

def store_false_positive(state: State) -> State:
    """오탐으로 판단된 이벤트를 저장합니다."""
    if state['is_false_positive']:
        event_id = state['event'].get('event_id', 'unknown')
        store_event(
            sql_result=state['sql_result'],
            event_id=event_id,
            confidence=state['confidence'],
            explanation=state['explanation']
        )
    return state