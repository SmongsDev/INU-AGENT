from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from ..config import Config
from .base import get_response_model

class State(TypedDict):
    messages: Annotated[list, add_messages]
    rag_model: str

def generate_answer(state: State):
    """Generate an answer."""
    question = state["messages"][0].content
    context = state["messages"][-1].content
    
    prompt = Config.load_prompt("generate").format(
        question=question,
        context=context
    )
    
    response = get_response_model(state["rag_model"]).invoke([{"role": "user", "content": prompt}])
    return {"messages": [response]}

