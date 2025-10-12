from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from agent.SQL_agent.tools.base import llm, run_query_tool, db
from agent.SQL_agent.config import Config

generate_query_system_prompt = open("agent/SQL_agent/prompts/generate_query_system_prompt.txt", "r").read()
generate_query_system_prompt = generate_query_system_prompt.format(
    dialect=db.dialect,
    tables=Config.ALLOW_TABLES
)

class State(TypedDict):
    messages: Annotated[list, add_messages]
    sql_model: str

def generate_query(state: State):
    system_message = {
        "role": "system",
        "content": generate_query_system_prompt,
    }
    llm_with_tools = llm.bind_tools([run_query_tool])
    response = llm_with_tools.invoke([system_message] + state["messages"])

    return {"messages": [response]}