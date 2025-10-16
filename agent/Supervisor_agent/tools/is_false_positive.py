from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from agent.Supervisor_agent.tools.base import get_supervisor_llm

is_false_positive_prompt = open("agent/Supervisor_agent/prompts/is_false_positive_prompt.txt", "r").read()

class State(TypedDict):
    messages: Annotated[list, add_messages]
    sup_model: str
    is_false_positive : bool

def is_false_positive(state: State):
    """보안 이벤트가 오탐(false positive)인지 판단합니다."""
    system_message = {
        "role": "system",
        "content": is_false_positive_prompt
    }
    llm = get_supervisor_llm(state["sup_model"])
    response = llm.invoke([system_message] + state["messages"])
    
    # LLM 응답을 boolean으로 변환
    response_text = response.content.strip().upper()
    is_fp = response_text == "TRUE"
    
    return {"is_false_positive": is_fp}   