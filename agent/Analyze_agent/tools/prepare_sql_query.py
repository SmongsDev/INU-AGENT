from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages
from langchain_core.messages import HumanMessage
from agent.Analyze_agent.config import Config

class State(TypedDict):
    messages: Annotated[list, add_messages]
    event: dict
    sql_result: str

def prepare_sql_query(state: State) -> State:
    """이벤트 정보를 기반으로 SQL 쿼리 생성을 위한 프롬프트를 준비합니다."""
    
    event = state['event']
    
    # 이벤트 정보 추출
    event_time = event.get('event_time', 'unknown')
    
    # 프롬프트 템플릿 로드 및 포맷팅
    prompt_template = Config.load_prompt('sql_query')
    query_prompt = prompt_template.format(event_time=event_time)
    
    # HumanMessage로 변환
    message = HumanMessage(content=query_prompt)
    
    return {
        'messages': [message]
    }

