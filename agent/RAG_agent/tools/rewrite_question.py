from langgraph.graph import MessagesState
from ..config import Config
from .base import response_model

def rewrite_question(state: MessagesState):
    """Rewrite the original user question."""
    messages = state["messages"]
    question = messages[0].content
    
    prompt = Config.load_prompt("rewrite").format(question=question)
    response = response_model.invoke([{"role": "user", "content": prompt}])
    
    return {"messages": [{"role": "user", "content": response.content}]}

