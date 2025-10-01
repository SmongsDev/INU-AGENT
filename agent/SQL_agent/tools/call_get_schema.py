from langgraph.graph import MessagesState
from agent.SQL_agent.tools.base import llm, get_schema_tool


def call_get_schema(state: MessagesState):
    llm_with_tools = llm.bind_tools([get_schema_tool], tool_choice="any")
    response = llm_with_tools.invoke(state["messages"])

    return {"messages": [response]}