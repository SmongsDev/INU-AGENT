from langgraph.graph import MessagesState
from ..config import Config
from .base import response_model

def generate_answer(state: MessagesState):
    """Generate an answer."""
    question = state["messages"][0].content
    context = state["messages"][-1].content
    
    prompt = Config.load_prompt("generate").format(
        question=question,
        context=context
    )
    
    response = response_model.invoke([{"role": "user", "content": prompt}])
    return {"messages": [response]}

