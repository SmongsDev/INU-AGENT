from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from agent.SQL_agent.tools.base import llm, get_schema_tool


class State(TypedDict):
    messages: Annotated[list, add_messages]
    sql_model: str

def call_get_schema(state: State):
    llm_with_tools = llm.bind_tools([get_schema_tool], tool_choice="any")
    response = llm_with_tools.invoke(state["messages"])

    return {"messages": [response]}