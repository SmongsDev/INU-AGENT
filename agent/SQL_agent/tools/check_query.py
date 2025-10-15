from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from agent.SQL_agent.tools.base import llm, run_query_tool

check_query_system_prompt = open("agent/SQL_agent/prompts/check_query_system_prompt.txt", "r").read()

class State(TypedDict):
    messages: Annotated[list, add_messages]
    sql_model: str

def check_query(state: State):
    system_message = {
        "role": "system",
        "content": check_query_system_prompt,
    }

    tool_call = state["messages"][-1].tool_calls[0]
    user_message = {"role": "user", "content": tool_call["args"]["query"]}
    llm_with_tools = llm.bind_tools([run_query_tool], tool_choice="any")
    response = llm_with_tools.invoke([system_message, user_message])
    response.id = state["messages"][-1].id

    return {"messages": [response]}