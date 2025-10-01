from langgraph.graph import StateGraph, START, END, MessagesState
from langgraph.prebuilt import ToolNode, tools_condition

from .tools.base import retriever_tool
from .tools.generate_query import generate_query_or_respond
from .tools.grade_documents import grade_documents
from .tools.rewrite_question import rewrite_question
from .tools.generate_answer import generate_answer

def RAG_agent():
    """Create and return a RAG agent workflow."""
    workflow = StateGraph(MessagesState)

    # Define nodes
    workflow.add_node(generate_query_or_respond)
    workflow.add_node("retrieve", ToolNode([retriever_tool]))
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