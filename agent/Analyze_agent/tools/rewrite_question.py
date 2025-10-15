from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from ..config import Config
from .base import get_response_model


class State(TypedDict):
    messages: Annotated[list, add_messages]
    rag_model: str

def rewrite_question(state: State):
    """Rewrite the original user question."""
    messages = state["messages"]
    question = messages[0].content
    
    prompt = Config.load_prompt("rewrite").format(question=question)
    response = get_response_model(state["rag_model"]).invoke([{"role": "user", "content": prompt}])
    
    return {"messages": [{"role": "user", "content": response.content}]}

