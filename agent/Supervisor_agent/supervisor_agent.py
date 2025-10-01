import os
from typing import Annotated
from langchain_core.tools import tool, InjectedToolCallId
from langgraph.prebuilt import InjectedState
from langgraph.graph import MessagesState, END, StateGraph, START
from langgraph.types import Command
from langgraph.prebuilt import create_react_agent
from agent.SQL_agent.SQL_agent import SQL_agent
from agent.RAG_agent.RAG import RAG_agent

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

SQL_agent = SQL_agent()
RAG_agent = RAG_agent()

# Ensure unique node names for LangGraph nodes to avoid "Node `...` already present" errors
if hasattr(SQL_agent, "name"):
    SQL_agent.name = "SQL_agent"
if hasattr(RAG_agent, "name"):
    RAG_agent.name = "RAG_agent"

def create_handoff_tool(*, agent_name: str, description: str | None = None):
    name = f"transfer_to_{agent_name}"
    description = description or f"Ask {agent_name} for help."

    @tool(name, description=description)
    def handoff_tool(
        state: Annotated[MessagesState, InjectedState],
        tool_call_id: Annotated[str, InjectedToolCallId],
    ) -> Command:
        tool_message = {
            "role": "tool",
            "content": f"Successfully transferred to {agent_name}",
            "name": name,
            "tool_call_id": tool_call_id,
        }
        return Command(
            goto=agent_name,  
            update={**state, "messages": state["messages"] + [tool_message]},  
            graph=Command.PARENT,  
        )

    return handoff_tool


# Handoffs
assign_to_SQL_agent = create_handoff_tool(
    agent_name="SQL_agent",
    description="Assign task to a SQL agent.",
)

assign_to_RAG_agent = create_handoff_tool(
    agent_name="RAG_agent",
    description="Assign task to a RAG agent.",
)

supervisor_agent = create_react_agent(
    model="openai:gpt-4.1",
    tools=[assign_to_SQL_agent, assign_to_RAG_agent],
    prompt=(
        "You are a supervisor managing two agents:\n"
        "- a SQL agent. Assign SQL-related tasks to this agent\n"
        "- a RAG agent. Assign RAG-related tasks to this agent\n"
        "Assign work to one agent at a time, do not call agents in parallel.\n"
        "Do not do any work yourself."
    ),
    name="supervisor",
)


# Define the multi-agent supervisor graph
supervisor = (
    StateGraph(MessagesState)
    # NOTE: `destinations` is only needed for visualization and doesn't affect runtime behavior
    .add_node(supervisor_agent, destinations=("SQL_agent", "RAG_agent", END))
    .add_node(SQL_agent)
    .add_node(RAG_agent)
    .add_edge(START, "supervisor")
    # always return back to the supervisor
    .add_edge("SQL_agent", "supervisor")
    .add_edge("RAG_agent", "supervisor")
    .compile()
)

for chunk in supervisor.stream(
    {
        "messages": [
            {
                "role": "user",
                "content": """
                2025년 9월 15일 발생한 로그 중 arn:aws:iam::093342385579:user/Tedy가 발생시킨 cloud trail 로그랑 request_parameters에 arn:aws:iam::093342385579:role/stratus-red-team-ec2-enumerate-role이 있는 로그를 확인 후 연관 지어서 타임라인을 구성해서 어떤 위협행위를 했는지 마이터 어택 매핑해줘
                """,
            }
        ]
    },
):
    print(chunk)

final_message_history = chunk["supervisor"]["messages"]