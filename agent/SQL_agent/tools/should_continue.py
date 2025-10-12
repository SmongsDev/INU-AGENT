from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from typing import Literal
from langgraph.graph import END

class State(TypedDict):
    messages: Annotated[list, add_messages]
    sql_model: str

def should_continue(state: State) -> Literal[END, "check_query"]:
    messages = state["messages"]
    last_message = messages[-1]
    if not last_message.tool_calls:
        return END
    else:
        return "check_query"
