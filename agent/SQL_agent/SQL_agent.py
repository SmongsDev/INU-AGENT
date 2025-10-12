from langsmith import Client
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from typing import TypedDict, Annotated

from agent.SQL_agent.tools.base import get_schema_node, run_query_node
from agent.SQL_agent.tools.list_tables import list_tables
from agent.SQL_agent.tools.call_get_schema import call_get_schema
from agent.SQL_agent.tools.generate_query import generate_query
from agent.SQL_agent.tools.check_query import check_query
from agent.SQL_agent.tools.should_continue import should_continue

client = Client()

class State(TypedDict):
    messages: Annotated[list, add_messages]
    sql_model: str

def SQL_agent():
    builder = StateGraph(State)
    builder.add_node(list_tables)
    builder.add_node(call_get_schema)
    builder.add_node(get_schema_node, "get_schema")
    builder.add_node(generate_query)
    builder.add_node(check_query)
    builder.add_node(run_query_node, "run_query")

    builder.add_edge(START, "list_tables")
    builder.add_edge("list_tables", "call_get_schema")
    builder.add_edge("call_get_schema", "get_schema")
    builder.add_edge("get_schema", "generate_query")
    builder.add_conditional_edges(
        "generate_query",
        should_continue,
    )
    builder.add_edge("check_query", "run_query")
    builder.add_edge("run_query","generate_query")

    agent = builder.compile()
    return agent
