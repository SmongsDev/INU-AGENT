from langchain_core.messages import AIMessage
from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from agent.SQL_agent.tools.base import tools

class State(TypedDict):
    messages: Annotated[list, add_messages]
    sql_model: str

def list_tables(state: State):
    tool_call = {
        "name": "sql_db_list_tables",
        "args": {},
        "id": "list_tables",
        "type": "tool_call",
    }
    tool_call_message = AIMessage(content="", tool_calls=[tool_call])

    list_tables_tool = next(tool for tool in tools if tool.name == "sql_db_list_tables")
    tool_message = list_tables_tool.invoke(tool_call)
    response = AIMessage(f"Available tables: {tool_message.content}")

    return {"messages": [tool_call_message, tool_message, response]}