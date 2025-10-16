from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from typing import TypedDict, Annotated

from agent.SQL_agent.SQL_agent import SQL_agent
from agent.Analyze_agent.tools.prepare_sql_query import prepare_sql_query
from agent.Analyze_agent.tools.save_sql_result import save_sql_result
from agent.Analyze_agent.tools.retrieve import retrieve_similar_events
from agent.Analyze_agent.tools.analyze import analyze_event
from agent.Analyze_agent.tools.store import store_false_positive

class State(TypedDict):
    messages: Annotated[list, add_messages]
    event: dict
    similar_events: list
    sql_result: str
    is_false_positive: bool
    explanation: str
    confidence: float
    retrive_cnt: int

class Input(TypedDict):
    event: dict
    retrive_cnt: int

class Output(TypedDict):
    is_false_positive: bool
    confidence: float
    explanation: str

def Analyze_agent():
    """보안 이벤트 분석 에이전트 워크플로우를 생성하고 반환합니다."""
    
    # SQL_agent 인스턴스 생성
    sql_agent_instance = SQL_agent()
    
    # 그래프 구성
    workflow = StateGraph(State, input=Input, output=Output)

    # 노드 추가
    workflow.add_node('prepare_sql', prepare_sql_query)
    workflow.add_node("SQL_agent", sql_agent_instance)
    workflow.add_node('save_sql_result', save_sql_result)
    workflow.add_node('retrieve', retrieve_similar_events)
    workflow.add_node('analyze', analyze_event)
    workflow.add_node('store', store_false_positive)

    # 엣지 추가 - START -> prepare_sql -> SQL_agent -> save_sql_result -> retrieve -> analyze -> store -> END
    workflow.add_edge(START, 'prepare_sql')
    workflow.add_edge('prepare_sql', "SQL_agent")
    workflow.add_edge("SQL_agent", 'save_sql_result')
    workflow.add_edge('save_sql_result', 'retrieve')
    workflow.add_edge('retrieve', 'analyze')
    workflow.add_edge('analyze', 'store')
    workflow.add_edge('store', END)
    
    return workflow.compile()