import json
from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from langchain_core.messages import HumanMessage, SystemMessage
from agent.Analyze_agent.tools.base import get_model
from agent.Analyze_agent.config import Config

class State(TypedDict):
    messages: Annotated[list, add_messages]
    event: dict
    similar_events: list
    confidence: float
    is_false_positive: bool
    explanation: str
    model_name: str

def analyze_event(state: State) -> State:
    """이벤트를 분석하여 정오탐 여부를 판단합니다."""
    
    # 모델 가져오기
    model_name = state.get('model_name', None)
    model = get_model(model_name)
    
    # 프롬프트 로드
    analysis_prompt = SystemMessage(content=Config.load_prompt("analyze"))
    
    # 유사 이벤트 포맷팅
    similar_events_text = "\n\n".join([
        f"Event {i+1}:\n{doc.page_content}\nMetadata: {doc.metadata}"
        for i, doc in enumerate(state['similar_events'])
    ])
    
    messages = [
        analysis_prompt,
        HumanMessage(content=f"""
현재 이벤트:
{state['event']}

유사 이벤트들:
{similar_events_text if similar_events_text else "유사 이벤트 없음"}
        """)
    ]

    response = model.invoke(messages)
    
    # JSON 파싱 시도
    try:
        # JSON 블록 추출
        content = response.content.strip()
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
        
        result = json.loads(content)
        is_false_positive = result.get("is_false_positive", False)
        confidence = result.get("confidence", 0.0)
        explanation = result.get("explanation", response.content)
    except (json.JSONDecodeError, IndexError, AttributeError):
        # JSON 파싱 실패 시 텍스트 분석
        is_false_positive = "false positive" in response.content.lower() or "오탐" in response.content
        confidence = 0.0
        explanation = response.content
    
    return {
        'is_false_positive': is_false_positive,
        'confidence': confidence,
        'explanation': explanation,
        'messages': [messages[-1], response],
    }

