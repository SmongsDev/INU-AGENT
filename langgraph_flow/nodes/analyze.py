import os
from typing import TypedDict
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain_core.documents import Document

class State(TypedDict):
    event_summary: str
    similar_events: list[Document]
    is_false_positive: bool
    explanation: str

def load_prompt_template() -> str:
    with open("prompts/analyze_prompt.txt", "r") as f:
        return f.read()

def analyze_event(state: State) -> State:
    """
    LLM을 사용하여 보안 이벤트의 정오탐 여부를 분석합니다.
    
    Args:
        state: 현재 상태
            - event: CloudTrailEvent
            - event_summary: str
            - similar_events: list
    
    Returns:
        Dict:
            - is_false_positive: bool
            - explanation: str
    """
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0
    )
    
    template = load_prompt_template()
    prompt = PromptTemplate(
        template=template,
        input_variables=["event_summary", "similar_events"]
    )
    
    chain = prompt | llm
    
    response = chain.invoke({
        "event_summary": state["event_summary"],
        "similar_events": state["similar_events"]
    })
    analysis_result = response.content  # Extract string content

    # LLM의 응답을 파싱하여 필요한 형식으로 변환
    is_false_positive = "false positive" in analysis_result.lower()
    explanation = analysis_result
    
    return {
        "is_false_positive": is_false_positive,
        "explanation": explanation
    }