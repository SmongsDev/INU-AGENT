import os
from typing import TypedDict, Annotated
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph.message import add_messages

def load_prompt() -> str:
    """분석 프롬프트를 로드합니다."""
    with open("prompts/analyze_prompt.txt", "r") as f:
        return f.read()

class State(TypedDict):
    messages: Annotated[list, add_messages]
    event_summary: str
    similar_events: list
    is_false_positive: bool
    explanation: str

def analyze_event(state: State) -> State:
    """이벤트를 분석하여 정오탐 여부를 판단합니다."""
    model = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0.1,
        api_key=os.environ.get("OPENAI_API_KEY")
    )
    
    messages = [
        SystemMessage(content=load_prompt()),
        HumanMessage(content=f"""
        현재 이벤트:
        {state['event_summary']}
        
        유사 이벤트들:
        {state['similar_events']}
        """)
    ]
    
    res = model.invoke(messages)
    is_false_positive = "false positive" in res.content.lower()
    
    return {
        'is_false_positive': is_false_positive,
        'explanation': res.content,
        'messages': [messages[-1], res],
    } 