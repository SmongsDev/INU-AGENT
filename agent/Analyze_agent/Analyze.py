from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from typing import TypedDict, Annotated
from langgraph.prebuilt import ToolNode, tools_condition

from .tools.base import get_retriever_tool
from .tools.generate_query import generate_query_or_respond
from .tools.grade_documents import grade_documents
from .tools.rewrite_question import rewrite_question
from .tools.generate_answer import generate_answer

class State(TypedDict):
    messages: Annotated[list, add_messages]
    rag_model: str
    retrive_cnt: int

def RAG_agent():
    """Create and return a RAG agent workflow."""
    workflow = StateGraph(State)

    # Define retrive node
    def retrive_node(state: State):
        retrive_cnt = state.get("retrive_cnt", 7)
        return ToolNode([get_retriever_tool(retrive_cnt)])
    
    # Define nodes
    workflow.add_node(generate_query_or_respond)
    workflow.add_node("retrieve", retrive_node)
    workflow.add_node(rewrite_question)
    workflow.add_node(generate_answer)

    # Add edges
    workflow.add_edge(START, "generate_query_or_respond")

    # Decide whether to retrieve
    workflow.add_conditional_edges(
        "generate_query_or_respond",
        tools_condition,
        {
            "tools": "retrieve",
            END: END,
        },
    )

    # Add conditional edges after retrieval
    workflow.add_conditional_edges(
        "retrieve",
        grade_documents,
        {
            "generate_answer": "generate_answer",
            "rewrite_question": "rewrite_question"
        }
    )

    workflow.add_edge("generate_answer", END)
    workflow.add_edge("rewrite_question", "generate_query_or_respond")

    # Compile and return
    return workflow.compile()