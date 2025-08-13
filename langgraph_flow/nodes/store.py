from typing import TypedDict
from langchain_core.documents import Document
from langgraph_flow.nodes.rag.vector_store import get_vector_store
from app.schemas.cloudtrail import CloudTrailEvent
from app.db.session import get_db
from app.db.models import CloudTrail
from sqlalchemy import select

def update_false_positive_status(event: CloudTrailEvent, is_false_positive: bool) -> None:
    """CloudTrail 이벤트의 오탐 여부를 업데이트합니다.

    Args:
        event (CloudTrailEvent): 업데이트할 CloudTrail 이벤트
        is_false_positive (bool): 오탐 여부
    """
    db = next(get_db())
    try:
        # cloudtrail 테이블의 is_false_positive 컬럼 업데이트
        stmt = select(CloudTrail).where(CloudTrail.event_id == event.event_id)
        result = db.execute(stmt)
        cloudtrail_event = result.scalar_one_or_none()
        
        if not cloudtrail_event:
            raise ValueError(f"이벤트 ID {event.event_id}를 찾을 수 없습니다.")
        
        cloudtrail_event.is_false_positive = is_false_positive
        db.commit()
    finally:
        db.close()

"""
이 노드는 오탐으로 판단된 이벤트를 벡터 저장소에 저장합니다.
State
    event: 원본 이벤트
    event_summary: 이벤트 요약
    is_false_positive: 오탐 여부
    explanation: 오탐 설명
"""

def store_document(event_summary: str, explanation: str, event_id: str) -> None:
    """이벤트 정보를 벡터 스토어에 저장합니다.

    Args:
        event_summary (str): 이벤트 요약
        explanation (str): 이벤트 설명
        event_id (str): 이벤트 ID
    """
    vector_store = get_vector_store()
    vector_store.add_documents([
        Document(
            page_content=f"이벤트 요약: {event_summary}\n설명: {explanation}",
            metadata={
                'event_id': event_id
            }
        )
    ])

class State(TypedDict):
    event: CloudTrailEvent
    event_summary: str
    is_false_positive: bool
    explanation: str

def store_false_positive(state: State) -> State:
    """오탐으로 판단된 이벤트를 저장합니다."""
    if state['is_false_positive']:
        store_document(state['event_summary'], state['explanation'], state['event'].event_id)
        update_false_positive_status(state['event'], state['is_false_positive'])
    return state