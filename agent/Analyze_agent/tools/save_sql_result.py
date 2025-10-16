from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages

class State(TypedDict):
    messages: Annotated[list, add_messages]
    event: dict
    similar_events: list
    sql_result: str
    is_false_positive: bool
    explanation: str
    retrive_cnt: int

def save_sql_result(state: State) -> State:
    """SQL_agent의 실행 결과를 sql_result에 저장합니다."""
    
    # messages에서 마지막 AI 응답 추출 (SQL_agent의 결과)
    messages = state['messages']
    if messages:
        last_message = messages[-1]
        # AIMessage 또는 dict 형태의 메시지에서 content 추출
        if hasattr(last_message, 'content'):
            sql_result = last_message.content
        else:
            sql_result = str(last_message.get('content', ''))
    else:
        sql_result = ""
    
    return {
        'sql_result': sql_result
    }

