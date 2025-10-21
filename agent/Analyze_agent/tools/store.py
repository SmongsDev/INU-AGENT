from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from agent.Analyze_agent.tools.base import store_event
from app.db.session import SessionLocal
from app.db.models import FalsePositiveLog

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
    event_id = state['event'].get('id')
    
    # 벡터 DB에 저장
    store_event(
        sql_result=state['sql_result'],
        event_id=event_id,
        is_false_positive=state['is_false_positive'],
        confidence=state['confidence'],
        explanation=state['explanation']
    )
    
    # false_positive_log 테이블에 저장
    if event_id:
        db = SessionLocal()
        try:
            false_positive_log = FalsePositiveLog(
                id=event_id,
                confidence=state['confidence'],
                reason=state['explanation'],
                result=state['is_false_positive']
            )
            
            db.add(false_positive_log)
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"Error storing to false_positive_log: {e}")
        finally:
            db.close()
    
    return state