from langgraph.graph import END, StateGraph, START
from langgraph.prebuilt import create_react_agent
from langgraph.graph.message import add_messages
from typing import TypedDict, Annotated, Literal

from agent.SQL_agent.SQL_agent import SQL_agent
from agent.RAG_agent.RAG import RAG_agent
from agent.Analyze_agent.Analyze import Analyze_agent
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

assign_to_Mapping = create_handoff_tool(
    agent_name="Mapping",
    description="Assign task to a Mapping agent for threat detection mapping to MITRE ATT&CK Cloud Matrix.",
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
        .add_node(Analyze_agent_instance)
        .add_node("Mapping", mapping)
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
        .add_edge("Mapping", "supervisor")
        .compile()
    )
    
    return supervisor_graph

if __name__ == "__main__":

    event = {
    "id": "38ef2c1d-3eb2-4dd4-8c63-7c24d1f9e6f8",
    "event_id": "38ef2c1d-3eb2-4dd4-8c63-7c24d1f9e6f8",
    "event_version": "1.10",
    "event_time": "2025-09-01 15:31:00+00",
    "event_source": "ec2.amazonaws.com",
    "event_name": "DescribeInstances",
    "event_category": "Management",
    "event_type": "AwsApiCall",
    "aws_region": "ap-northeast-2",
    "read_only": True,
    "request_id": "09543ac4-6406-4995-8a10-7d32f1181868",
    "source_ip": "3.34.253.12",
    "user_agent": "Boto3/1.40.17 md/Botocore#1.40.21 md/awscrt#0.23.8 ua/2.1 os/linux#6.1.144-170.251.amzn2023.x86_64 md/arch#x86_64 lang/python#3.9.23 md/pyimpl#CPython m/Z,b,F cfg/retry-mode#adaptive Botocore/1.40.21",
    "management_event": True,
    "recipient_account_id": "093342385579",
    "session_credential_from_console": None,
    "shared_event_id": None,
    "error_code": None,
    "error_message": None,
    "user_identity": "{\"arn\": \"arn:aws:iam::093342385579:user/Tedy\", \"type\": \"IAMUser\", \"userName\": \"Tedy\", \"accountId\": \"093342385579\", \"accessKeyId\": \"AKIARLO5DYWV4QNIF733\", \"principalId\": \"AIDARLO5DYWVSY6CA4BIJ\"}",
    "tls_details": "{\"tlsVersion\": \"TLSv1.3\", \"cipherSuite\": \"TLS_AES_128_GCM_SHA256\", \"clientProvidedHostHeader\": \"ec2.ap-northeast-2.amazonaws.com\"}",
    "request_parameters": "{\"filterSet\": {}, \"maxResults\": 1000, \"instancesSet\": {}}",
    "response_elements": "null",
    "insight_details": None,
    "resources": None
  }

    state = {
        "messages": [{"role": "user", "content": "cloudtrail 테이블에서 2025-09-01 15:28:30+00 기준 앞뒤로 10초 로그를 확인하고 오탐인지 아닌지 판단해봐."}],
        "event": event,
        "sup_model": "gpt-4.1",
        "sql_model": "gpt-4.1",
        "rag_model": "gpt-4.1",
        "retrive_cnt": 5,
        "collection_name": "cloud_matrix",
        "report_option": {
            "timeline": True,
            "mapping": True,
        },
    }
    supervisor = supervisor(state)
    for chunk in supervisor.stream(state):
        print(chunk)