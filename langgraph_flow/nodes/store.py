from typing import TypedDict
from langchain_core.documents import Document
from langgraph_flow.nodes.rag.vector_store import get_vector_store

class State(TypedDict):
    event: dict
    event_summary: str
    is_false_positive: bool
    explanation: str

def store_false_positive(state: State) -> State:
    """오탐으로 판단된 이벤트를 저장합니다."""
    if state['is_false_positive']:
        vector_store = get_vector_store()
        vector_store.add_documents([
            Document(
                page_content=state['event_summary'],
                metadata={
                    'event_id': state['event']['event_id'],
                    'explanation': state['explanation']
                }
            )
        ])
    return state 