from langgraph.graph import END, StateGraph, START
from langgraph.prebuilt import create_react_agent
from langgraph.graph.message import add_messages
from typing import TypedDict, Annotated, Literal

from agent.SQL_agent.SQL_agent import SQL_agent
from agent.RAG_agent.RAG import RAG_agent
from agent.Analyze_agent.Analyze import Analyze_agent
from agent.Supervisor_agent.config import Config
from agent.Supervisor_agent.tools.base import create_handoff_tool, get_supervisor_llm

class State(TypedDict):
    messages: Annotated[list, add_messages]
    sup_model: str
    sql_model: str
    rag_model: str
    retrive_cnt: int
    report_option: dict
    collection_name: str

    event: dict
    similar_events: list
    sql_result: str
    is_false_positive: bool
    explanation: str
    confidence: float

# Create agent instances
SQL_agent_instance = SQL_agent()
RAG_agent_instance = RAG_agent()
Analyze_agent_instance = Analyze_agent()

# Ensure unique node names for LangGraph nodes
if hasattr(SQL_agent_instance, "name"):
    SQL_agent_instance.name = "SQL_agent"
if hasattr(RAG_agent_instance, "name"):
    RAG_agent_instance.name = "RAG_agent"
if hasattr(Analyze_agent_instance, "name"):
    Analyze_agent_instance.name = "Analyze_agent"

# Create handoff tools
assign_to_SQL_agent = create_handoff_tool(
    agent_name="SQL_agent",
    description="Assign task to a SQL agent for database operations.",
)

assign_to_RAG_agent = create_handoff_tool(
    agent_name="RAG_agent",
    description="Assign task to a RAG agent for document retrieval and question answering.",
)

def route_after_analyze(state: State) -> Literal["supervisor", "__end__"]:
    """Analyze_agent 결과에 따라 라우팅을 결정합니다."""
    is_false_positive = state.get("is_false_positive", False)
    
    if is_false_positive:
        # 오탐으로 판단되면 종료
        return "__end__"
    else:
        # 실탐으로 판단되면 supervisor로 전달하여 추가 분석
        return "supervisor"

def create_supervisor_agent(model_name: str):
    """Supervisor agent를 생성합니다."""
    model = model_name or Config.DEFAULT_SUP_MODEL
    
    return create_react_agent(
        model=get_supervisor_llm(model),
        tools=[assign_to_SQL_agent, assign_to_RAG_agent],
        prompt=Config.load_prompt("supervisor"),
        name="supervisor",
    )

def supervisor(state: State):
    """Supervisor workflow를 생성하고 반환합니다."""
    supervisor_agent = create_supervisor_agent(state["sup_model"])
    
    # Define the multi-agent supervisor graph
    supervisor_graph = (
        StateGraph(State)
        .add_node(supervisor_agent, destinations=("SQL_agent", "RAG_agent", END))
        .add_node(SQL_agent_instance)
        .add_node(RAG_agent_instance)
        .add_node(Analyze_agent_instance)
        # START -> Analyze_agent로 시작
        .add_edge(START, "Analyze_agent")
        # Analyze_agent 결과에 따라 조건부 라우팅
        .add_conditional_edges(
            "Analyze_agent",
            route_after_analyze,
            {"supervisor": "supervisor", "__end__": END}
        )
        # 각 에이전트는 supervisor로 돌아감
        .add_edge("SQL_agent", "supervisor")
        .add_edge("RAG_agent", "supervisor")
        .compile()
    )
    
    return supervisor_graph