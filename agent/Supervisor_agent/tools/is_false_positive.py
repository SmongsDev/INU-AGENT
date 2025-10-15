from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from agent.Supervisor_agent.tools.base import get_supervisor_llm

is_false_positive_prompt = open("agent/Supervisor_agent/prompts/is_false_positive_prompt.txt", "r").read()

class State(TypedDict):
    messages: Annotated[list, add_messages]
    sup_model: str

def is_false_positive(state: State):
    system_message = {
        "role": "system",
        "content": is_false_positive_prompt
    }
    llm_with_tools = get_supervisor_llm(state["sup_model"])
    response = llm_with_tools.invoke([system_message] + state["messages"])

    return {"messages": [response]}