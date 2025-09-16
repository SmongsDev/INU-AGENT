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
    with open("prompts/analyze_prompt.txt", "r", encoding="utf-8") as f:
        return f.read()

def analyze_event(state: State) -> State:
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0.1
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
    analysis_result = response.content

    is_false_positive = "false positive" in analysis_result.lower()
    explanation = analysis_result
    
    return {
        "is_false_positive": is_false_positive,
        "explanation": explanation
    }