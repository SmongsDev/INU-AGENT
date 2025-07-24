from datetime import datetime
from typing import Optional, Dict, Any
from app.schemas.cloudtrail import CloudTrailEvent

def convert_cloudtrail_to_text(event: CloudTrailEvent) -> str:
    """
    CloudTrail 이벤트를 임베딩 검색에 최적화된 텍스트 형식으로 변환합니다.
    
    Args:
        event (CloudTrailEvent): CloudTrail 이벤트 객체
        
    Returns:
        str: 변환된 텍스트 문자열
    """
    # 핵심 이벤트 정보를 자연스러운 문장으로 구성
    core_event = (
        f"AWS 사용자가 {event.event_time.strftime('%Y년 %m월 %d일 %H:%M:%S')}에 "
        f"{event.aws_region or '알 수 없는 리전'}에서 {event.event_source}의 "
        f"{event.event_name} 작업을 수행했습니다."
    )
    
    # 사용자 식별 정보를 문장으로 구성
    user_context = []
    if event.user_identity:
        user_type = event.user_identity.get('type', 'Unknown')
        user_arn = event.user_identity.get('arn', 'N/A')
        account_id = event.user_identity.get('accountId', 'N/A')
        user_context.append(
            f"이 작업은 {account_id} 계정의 {user_type} 유형 사용자({user_arn})에 의해 수행되었습니다."
        )
    
    # 네트워크 컨텍스트를 문장으로 구성
    network_context = []
    if event.source_ip or event.user_agent:
        network_info = (
            f"사용자는 IP 주소 {event.source_ip or '알 수 없음'}에서 "
            f"{event.user_agent or '알 수 없는 클라이언트'}를 사용하여 접근했습니다."
        )
        network_context.append(network_info)
    
    # 작업 세부 정보를 문장으로 구성
    action_details = []
    if event.request_parameters:
        params = [f"{k}={v}" for k, v in event.request_parameters.items()]
        action_details.append(f"요청된 파라미터: {', '.join(params)}")
    
    if event.response_elements:
        action_details.append("작업 결과: " + 
            ' '.join(f"{k}={v}" for k, v in event.response_elements.items()))
    
    # 에러 정보를 문장으로 구성
    error_info = []
    if event.error_code:
        error_info.append(
            f"작업 중 오류가 발생했습니다: {event.error_code} - {event.error_message or '상세 정보 없음'}"
        )
    
    # 리소스 정보를 문장으로 구성
    resource_info = []
    if event.resources:
        if isinstance(event.resources, list):
            for resource in event.resources:
                if isinstance(resource, dict):
                    resource_info.append(
                        f"영향받은 리소스: 유형={resource.get('type', 'N/A')}, "
                        f"이름={resource.get('name', 'N/A')}, "
                        f"ARN={resource.get('arn', 'N/A')}"
                    )
        elif isinstance(event.resources, dict):
            resource_info.append(
                f"영향받은 리소스: 유형={event.resources.get('type', 'N/A')}, "
                f"ARN={event.resources.get('ARN', event.resources.get('arn', 'N/A'))}, "
                f"계정={event.resources.get('accountId', 'N/A')}"
            )
    
    # 모든 컨텍스트를 하나의 일관된 텍스트로 결합
    all_sections = [
        core_event,
        *user_context,
        *network_context,
        *action_details,
        *error_info,
        *resource_info
    ]
    
    return " ".join(all_sections)