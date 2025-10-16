from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from typing import TypedDict, Annotated

from agent.SQL_agent.SQL_agent import SQL_agent
from agent.Analyze_agent.tools.prepare_sql_query import prepare_sql_query
from agent.Analyze_agent.tools.save_sql_result import save_sql_result
from agent.Analyze_agent.tools.retrieve import retrieve_similar_events
from agent.Analyze_agent.tools.analyze import analyze_event
from agent.Analyze_agent.tools.store import store_false_positive

class State(TypedDict):
    messages: Annotated[list, add_messages]
    event: dict
    similar_events: list
    sql_result: str
    is_false_positive: bool
    explanation: str
    confidence: float
    retrive_cnt: int

class Input(TypedDict):
    event: dict
    retrive_cnt: int

class Output(TypedDict):
    is_false_positive: bool
    confidence: float
    explanation: str

def Analyze_agent():
    """보안 이벤트 분석 에이전트 워크플로우를 생성하고 반환합니다."""
    
    # SQL_agent 인스턴스 생성
    sql_agent_instance = SQL_agent()
    
    # 그래프 구성
    workflow = StateGraph(State, input=Input, output=Output)

    # 노드 추가
    workflow.add_node('prepare_sql', prepare_sql_query)
    workflow.add_node("SQL_agent", sql_agent_instance)
    workflow.add_node('save_sql_result', save_sql_result)
    workflow.add_node('retrieve', retrieve_similar_events)
    workflow.add_node('analyze', analyze_event)
    workflow.add_node('store', store_false_positive)

    # 엣지 추가 - START -> prepare_sql -> SQL_agent -> save_sql_result -> retrieve -> analyze -> store -> END
    workflow.add_edge(START, 'prepare_sql')
    workflow.add_edge('prepare_sql', "SQL_agent")
    workflow.add_edge("SQL_agent", 'save_sql_result')
    workflow.add_edge('save_sql_result', 'retrieve')
    workflow.add_edge('retrieve', 'analyze')
    workflow.add_edge('analyze', 'store')
    workflow.add_edge('store', END)
    
    return workflow.compile()

if __name__ == "__main__":
    event =     {
    "event_id": "254245ea-cee6-41f5-88b6-909b6386ee3c",
    "event_version": "1.08",
    "event_time": "2025-09-15 05:12:54+00",
    "event_source": "sts.amazonaws.com",
    "event_name": "AssumeRole",
    "event_category": "Management",
    "event_type": "AwsApiCall",
    "aws_region": "ap-northeast-2",
    "read_only": True,
    "request_id": "f62b0f84-aea5-454a-a322-3979b33b8cdb",
    "source_ip": None,
    "user_agent": "ec2.amazonaws.com",
    "management_event": True,
    "recipient_account_id": "093342385579",
    "session_credential_from_console": None,
    "shared_event_id": None,
    "error_code": None,
    "error_message": None,
    "user_identity": "{\"arn\": \"\", \"type\": \"AWSService\", \"userName\": None, \"accountId\": \"\", \"accessKeyId\": None, \"principalId\": \"\"}",
    "tls_details": None,
    "request_parameters": "{\"roleArn\": \"arn:aws:iam::093342385579:role/stratus-red-team-ec2-enumerate-role\", \"roleSessionName\": \"i-06ccf911aa353ca1b\"}",
    "response_elements": "{\"credentials\": {\"expiration\": \"Sep 15, 2025, 11:22:09 AM\", \"accessKeyId\": \"ASIARLO5DYWVTSRA5YFD\", \"sessionToken\": \"IQoJb3JpZ2luX2VjEPX//////////wEaDmFwLW5vcnRoZWFzdC0yIkcwRQIgC7ozUVKcTkfGwH3bf3WomQOANfJ4i5rH8r0dN0hjY68CIQDtwQjP9jBOpT/K5TVnuQA7d8g0zYZFQ4Yfkky4tFs9wCrIBQhuEAAaDDA5MzM0MjM4NTU3OSIMJjrE4ugKHAYf+QoHKqUFAiAKrcWriIysqS+f0d9/XvwYRcmLDDW+xXeV/tOl3YTh4DhfhANOym4TkQsYVI2sVzhB/0B/4ixyCIjZlROdcJ+MzsBlenMXfDwesohPbBpznweDC3GyMAaQiXRy87WGXSVUw8R/spddYmXs+JyO/BDcA9V50UXYP1Nixx5afIq+GtMkuPA6erCmgxH8Km6MKKHpMvJ1v1T1C6zkJKR+tczu0kuYBeCpY4eduBmCi6QR3biZ8lYJsUtf5mci1Vw8hnQ8nSbFif3ra8vS8S34s8aGhx69OtEfH84Nu1bmMBa3ZhRLXPq/+9ik3cy5MDhsZTEUVI+YS4gU1XxTeqDtk3Q1HInktczCwl8igDraMIfBleGYWYzDlL6EXMCcq/Qc0rKMS3P0JShuOaga5tgWAFLovvVJ+mWIhicavI6Op7rvlh8t2mou7jJTEfIJTV6aehn0J9xqulccxZiNxy9sqJRQiIjG4wdsORK7AL0CdqP2P04rZQCGTZYOG9bFcP2AHLOWqCrCXR76KpCw8Pl/KQedQ1rad4NJRESUm22CM7Mmgvs9pO1QpmKiKRYvOZ1t5lGLrZ7V7buT2rbVFVhQv6IwOdslrrcIRrzIOha2ZCylrCppBawfITxW2GHyxU9GCiy8ykXSCpeDzJmKgviuswJksI5SCy9qLCg0NeAgEb/h0+G4bsU5FrkKgEZcZ866IkRpTH2Cg00taDfWgXnPdjNIlHvhgd0J8Lu6q8tKkGx+gG28DX1hnzH8u4t0vfd5uasCwmEBw0oq9xY1IOLeN4vOM5saKvS0zgGG/JYcAZdO+GuvuUmmMUqVkUSJAYpOM+JJ8/0VmeTDNFCq+DXzR+dEzhsa00tqhJb+4xP+HrjGNxsvpmBgiAUwjFi1k5Op4cc1JyIw1sCexgY6sQF4HPPFlGx+NnaHRG5sG0o9qW503NG3k7AIMMHjXmRH0eGsYQ+BwW1yfYfadNZLVFsjwdQ/02vjUOZp6J2kGs+Dsbnq5trzItbENFX1XauerAg9ECCr+/vfFzgo+ra6cV7cd2OdmF1pX6yGX0XoICuCrp4vpcIjsvpmouIKEPr/fzvP1Cxs/Kf+J1uU31swMXoSps5fkfOQdckLl/TaiXpiH+z/wZByodDc24N0hX3eHOY=\"}}",
    "insight_details": None,
    "resources": None
  }
    result = Analyze_agent().invoke({"event": event, "retrive_cnt": 5})
    print(result)