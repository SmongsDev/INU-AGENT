from langgraph.graph import END, StateGraph, START
from langgraph.prebuilt import create_react_agent
from langgraph.graph.message import add_messages
from typing import TypedDict, Annotated

from agent.SQL_agent.SQL_agent import SQL_agent
from agent.RAG_agent.RAG import RAG_agent
from agent.Supervisor_agent.tools.mapping import mapping
from agent.Supervisor_agent.config import Config
from agent.Supervisor_agent.tools.base import create_handoff_tool, get_supervisor_llm

class State(TypedDict):
    messages: Annotated[list, add_messages]
    sup_model: str
    sql_model: str
    rag_model: str
    retrive_cnt: int
    report_option: dict

# Create agent instances
SQL_agent_instance = SQL_agent()
RAG_agent_instance = RAG_agent()

# Ensure unique node names for LangGraph nodes
if hasattr(SQL_agent_instance, "name"):
    SQL_agent_instance.name = "SQL_agent"
if hasattr(RAG_agent_instance, "name"):
    RAG_agent_instance.name = "RAG_agent"

# Create handoff tools
assign_to_SQL_agent = create_handoff_tool(
    agent_name="SQL_agent",
    description="Assign task to a SQL agent for database operations.",
)

assign_to_RAG_agent = create_handoff_tool(
    agent_name="RAG_agent",
    description="Assign task to a RAG agent for document retrieval and question answering.",
)

assign_to_Mapping = create_handoff_tool(
    agent_name="Mapping",
    description="Assign task to a Mapping agent for threat detection mapping to MITRE ATT&CK Cloud Matrix.",
)

def create_supervisor_agent(model_name: str):
    """Supervisor agent를 생성합니다."""
    model = model_name or Config.DEFAULT_SUP_MODEL
    
    return create_react_agent(
        model=get_supervisor_llm(model),
        tools=[assign_to_SQL_agent, assign_to_RAG_agent, assign_to_Mapping],
        prompt=Config.load_prompt("supervisor"),
        name="supervisor",
    )

def supervisor(state: State):
    """Supervisor workflow를 생성하고 반환합니다."""
    supervisor_agent = create_supervisor_agent(state["sup_model"])
    
    # Define the multi-agent supervisor graph
    supervisor_graph = (
        StateGraph(State)
        .add_node(supervisor_agent, destinations=("SQL_agent", "RAG_agent", "Mapping", END))
        .add_node(SQL_agent_instance)
        .add_node(RAG_agent_instance)
        .add_node("Mapping", mapping)
        .add_edge(START, "supervisor")
        # always return back to the supervisor
        .add_edge("SQL_agent", "supervisor")
        .add_edge("RAG_agent", "supervisor")
        .add_edge("Mapping", "supervisor")
        .compile()
    )
    
    return supervisor_graph

if __name__ == "__main__":
    state = {
        #cloudtrail, ml_result -> 특정 지을 수 있어?
        #cloudtrail, ml_result SQL 시간이랑 전후 로그들 
        "cloudtrail":{},
        "ml_result":{},
        "messages": [{"role": "user", "content": "cloudtrail 테이블에서 2025-09-01 15:28:30+00 기준 앞뒤로 10초 로그를 확인하고 오탐인지 아닌지 판단해봐."}],
        "sup_model": "gpt-4.1",
        "sql_model": "gpt-4.1",
        "rag_model": "gpt-4.1",
        "retrive_cnt": 5,
        "report_option": {
            "timeline": True,
            "mapping": True,
        },
    }
    supervisor = supervisor(state)
    for chunk in supervisor.stream(state):
        print(chunk)