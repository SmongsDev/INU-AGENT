import os
import dotenv
from typing import TypedDict, Annotated
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langsmith import traceable
from .nodes.summarize import summarize_event
from .nodes.retrieve import retrieve_similar_events
from .nodes.analyze import analyze_event
from .nodes.store import store_false_positive
from app.schemas.cloudtrail import CloudTrailEvent

# 환경 변수 로드
dotenv.load_dotenv()

class State(TypedDict):
    messages: Annotated[list, add_messages]
    event: dict
    event_summary: str
    similar_events: list
    is_false_positive: bool
    explanation: str
    ml_confidence: float

@traceable(name="create_false_positive_detection_graph")
def create_graph() -> StateGraph:
    """정오탐 분석을 위한 그래프를 생성합니다."""
    builder = StateGraph(State)

    builder.add_node('summarize', summarize_event)
    builder.add_node('retrieve', retrieve_similar_events)
    builder.add_node('analyze', analyze_event)
    builder.add_node('store', store_false_positive)

    builder.add_edge(START, 'summarize')
    builder.add_edge('summarize', 'retrieve')
    builder.add_edge('retrieve', 'analyze')
    builder.add_edge('analyze', 'store')
    builder.add_edge('store', END)

    return builder.compile()

@traceable(name="process_security_event")
def process_security_event(event: dict, confidence: float = 0.0) -> dict:
    """보안 이벤트를 처리하고 정오탐 여부를 반환합니다."""
    graph = create_graph()
    result = graph.invoke(input={
        "event": event,
        "ml_confidence": confidence
    })
    return {
        "is_false_positive": result["is_false_positive"],
        "explanation": result["explanation"]
    }
