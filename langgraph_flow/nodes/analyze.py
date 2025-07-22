from fastapi import APIRouter, HTTPException
from langgraph_flow.nodes.analyze import analyze_event
from app.schemas.cloudtrail import CloudTrailEvent

router = APIRouter()

@router.post("/analyze-agent", response_model=dict)
async def analyze_event_route(event: CloudTrailEvent):
    try:
        # CloudTrail 이벤트를 상태 입력으로 변환
        state = {
            "event_id": event.event_id,
            "event_source": event.event_source,
            "event_name": event.event_name,
            "aws_region": event.aws_region,
            "event_time": event.event_time.isoformat(),
            "user_identity": event.user_identity,
            "request_parameters": event.request_parameters,
            "response_elements": event.response_elements,
            "error_code": event.error_code,
            "error_message": event.error_message,
            "messages": [],
            "is_suspicious": False,
            "analysis": ""
        }
        result = analyze_event(state)
        return {
            "is_suspicious": result["is_suspicious"],
            "analysis": result["analysis"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))