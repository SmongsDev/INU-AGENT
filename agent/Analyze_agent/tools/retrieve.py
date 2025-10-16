from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from agent.Analyze_agent.tools.base import vector_store

class State(TypedDict):
    messages: Annotated[list, add_messages]
    event: dict
    similar_events: list
    is_false_positive: bool
    explanation: str
    retrive_cnt: int

def retrieve_similar_events(state: State) -> State:
    """유사한 이벤트를 검색합니다."""
    retrive_cnt = state.get('retrive_cnt', 5)
    similar_events = vector_store.similarity_search(state['messages'][0].content, k=retrive_cnt)
    return {
        'similar_events': similar_events,
    }

