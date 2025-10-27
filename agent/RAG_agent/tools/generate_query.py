from .base import get_response_model, get_retriever_tool
from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages

class State(TypedDict):
    messages: Annotated[list, add_messages]
    rag_model: str
    retrive_cnt: int
    collection_name: str

def generate_query_or_respond(state: State):
    """Call the model to generate a response based on the current state. Given
    the question, it will decide to retrieve using the retriever tool, or simply respond to the user.
    """
    response = (
        get_response_model(state["rag_model"])
        .bind_tools([get_retriever_tool(state["retrive_cnt"])])
        .invoke(state["messages"])
    )
    return {"messages": [response]}

