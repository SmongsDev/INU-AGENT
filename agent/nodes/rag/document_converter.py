from datetime import datetime

def convert_cloudtrail_to_text(event: dict) -> str:    
    # 핵심 이벤트 정보를 자연스러운 문장으로 구성
    event_time = event.get('eventTime', '')
    if event_time:
        try:
            event_time = datetime.fromisoformat(event_time).strftime('%Y년 %m월 %d일 %H:%M:%S')
        except:
            event_time = event_time
    
    core_event = (
        f"AWS 사용자가 {event_time}에 "
        f"{event.get('aws_region') or '알 수 없는 리전'}에서 {event.get('eventSource', '')}의 "
        f"{event.get('eventName', '')} 작업을 수행했습니다."
    )
    
    # 사용자 식별 정보를 문장으로 구성
    user_context = []
    user_identity = event.get('user_identity')
    if user_identity:
        user_type = user_identity.get('type', 'Unknown')
        user_arn = user_identity.get('arn', 'N/A')
        account_id = user_identity.get('accountId', 'N/A')
        user_context.append(
            f"이 작업은 {account_id} 계정의 {user_type} 유형 사용자({user_arn})에 의해 수행되었습니다."
        )
    
    # 네트워크 컨텍스트를 문장으로 구성
    network_context = []
    source_ip = event.get('sourceIPAddress', event.get('source_ip'))
    user_agent = event.get('userAgent', event.get('user_agent'))
    if source_ip or user_agent:
        network_info = (
            f"사용자는 IP 주소 {source_ip or '알 수 없음'}에서 "
            f"{user_agent or '알 수 없는 클라이언트'}를 사용하여 접근했습니다."
        )
        network_context.append(network_info)
    
    # 작업 세부 정보를 문장으로 구성
    action_details = []
    request_parameters = event.get('request_parameters')
    if request_parameters:
        params = [f"{k}={v}" for k, v in request_parameters.items()]
        action_details.append(f"요청된 파라미터: {', '.join(params)}")
    
    response_elements = event.get('response_elements')
    if response_elements:
        action_details.append("작업 결과: " + 
            ' '.join(f"{k}={v}" for k, v in response_elements.items()))
    
    # 에러 정보를 문장으로 구성
    error_info = []
    error_code = event.get('error_code')
    if error_code:
        error_message = event.get('error_message', '상세 정보 없음')
        error_info.append(
            f"작업 중 오류가 발생했습니다: {error_code} - {error_message}"
        )
    
    # 리소스 정보를 문장으로 구성
    resource_info = []
    resources = event.get('resources')
    if resources:
        if isinstance(resources, list):
            for resource in resources:
                if isinstance(resource, dict):
                    resource_info.append(
                        f"영향받은 리소스: 유형={resource.get('type', 'N/A')}, "
                        f"이름={resource.get('name', 'N/A')}, "
                        f"ARN={resource.get('arn', 'N/A')}"
                    )
        elif isinstance(resources, dict):
            resource_info.append(
                f"영향받은 리소스: 유형={resources.get('type', 'N/A')}, "
                f"ARN={resources.get('ARN', resources.get('arn', 'N/A'))}, "
                f"계정={resources.get('accountId', 'N/A')}"
            )
    
    # ML 분석 결과를 문장으로 구성
    ml_analysis = []
    is_false_positive = event.get('is_false_positive')
    if is_false_positive is not None:
        if is_false_positive:
            ml_analysis.append("ML 분석 결과: 오탐(false positive)으로 판정되었습니다.")
        else:
            ml_analysis.append("ML 분석 결과: 실제 보안 위험으로 판정되었습니다.")
    
    # 모든 컨텍스트를 하나의 일관된 텍스트로 결합
    all_sections = [
        core_event,
        *user_context,
        *network_context,
        *action_details,
        *error_info,
        *resource_info,
        *ml_analysis
    ]
    
    return " ".join(all_sections)