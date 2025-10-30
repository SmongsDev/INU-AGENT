import json
import re
from datetime import datetime

from agent.Analyze_agent.Analyze import Analyze_agent
from agent.Supervisor_agent.supervisor_agent import Supervisor_agent
from report import generate_full_pdf
from app.db.session import SessionLocal
from app.db.models import AgentResult, AgentTotal, SeverityLevel, Settings
from app.services.notification_service import NotificationService

def is_unusual_time(timestamp: str) -> bool:
    try:
        # Parse timestamp
        if isinstance(timestamp, str):
            # Handle various timestamp formats
            if '+' in timestamp or 'Z' in timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                dt = datetime.fromisoformat(timestamp)
        else:
            return False
        
        hour = dt.hour
        
        # Business hours: 08:00 ~ 19:00 (8 <= hour < 19)
        if 8 <= hour < 19:
            return False  # Normal business hours
        else:
            return True   # Unusual time (outside business hours)
            
    except (ValueError, AttributeError, TypeError) as e:
        print(f"Failed to parse timestamp '{timestamp}': {e}")
        return False  # Default to False if parsing fails


def is_new_location(region: str) -> bool:

    if not region:
        return False  # Region 정보가 없으면 False
    
    # Expected region
    expected_region = "ap-northeast-2"
    
    if region.lower() == expected_region.lower():
        return False  # Expected region
    else:
        return True   # New/unusual location

def agent(event: dict, state: dict, group_id: str):
    analyze_agent = Analyze_agent()
    analyze_result = analyze_agent.invoke({"event": event, "retrive_cnt": 5})

    is_false_positive = analyze_result.get("is_false_positive")

    if is_false_positive:
        return None
    
    else:
        confidence = analyze_result.get("confidence", 0.0)
        explanation = analyze_result.get("explanation", "no explanation")
        event_id = event.get("event_id")
        event_time = event.get("event_time")
        user_identity = event.get("user_identity")
        request_parameters = event.get("request_parameters")

        user_prompt = f"오탐탐지 결과 {is_false_positive} 신뢰도 {confidence} 설명 {explanation} {event_id}, {event_time}, {user_identity}, request_parameters({request_parameters})를 SQL_agent와 RAG_agent를 통해 Mitre Attack 매핑해봐."

        sup_model = state.get("sup_model", "gpt-4.1")
        sql_model = state.get("sql_model", "gpt-4.1")
        rag_model = state.get("rag_model", "gpt-4.1")
        retrive_cnt = state.get("retrive_cnt", 5)
        report_option = state.get("report_option", {
            "timeline": True,
            "mapping": True,
        })
        
        supervisor_state = {
            "event": event,
            "messages": [{"role": "user", "content": user_prompt}],
            "sup_model": sup_model,
            "sql_model": sql_model,
            "rag_model": rag_model,
            "retrive_cnt": retrive_cnt,
            "report_option": report_option,
        }

        supervisor = Supervisor_agent(supervisor_state)
        supervisor_result = supervisor.invoke(supervisor_state)
        
        messages = supervisor_result.get("messages", [])
        if messages:
            # Get the last message from supervisor
            last_msg = messages[-1]
            content = str(last_msg.get("content", "")) if isinstance(last_msg, dict) else str(last_msg.content if hasattr(last_msg, "content") else "")
            
            # Try to extract JSON from the content
            try:
                json_str = None
                
                # Method 1: Try to find markdown code block (```json ... ``` or ``` ... ```)
                markdown_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', content, re.DOTALL)
                if markdown_match:
                    json_str = markdown_match.group(1).strip()
                
                # Method 2: Try to find raw JSON (fallback)
                if not json_str:
                    # Find outermost JSON object containing "severity"
                    start_idx = content.find('{')
                    if start_idx != -1:
                        brace_count = 0
                        for i in range(start_idx, len(content)):
                            if content[i] == '{':
                                brace_count += 1
                            elif content[i] == '}':
                                brace_count -= 1
                                if brace_count == 0:
                                    json_str = content[start_idx:i+1]
                                    break
                
                if not json_str or '"severity"' not in json_str:
                    return None
                
                report = json.loads(json_str)

                # Parse user_identity to extract ARN
                user_arn = "N/A"
                user_identity_str = event.get("user_identity", "")
                if user_identity_str:
                    try:
                        if isinstance(user_identity_str, str):
                            user_identity_dict = json.loads(user_identity_str)
                        else:
                            user_identity_dict = user_identity_str
                        user_arn = user_identity_dict.get("arn", "N/A")
                    except (json.JSONDecodeError, AttributeError, TypeError):
                        user_arn = "N/A"

                # Build detailed report_data dict
                report_data = {
                    "severity": report.get("severity", "N/A").lower(),
                    "accuracy": report.get("accuracy", 0.0),
                    "event_id": event.get("event_id", "N/A"),
                    "timestamp": event.get("event_time", "N/A"),
                    "source": event.get("event_source", "N/A"),
                    "event_name": event.get("event_name", "N/A"),
                    "user_arn": user_arn,
                    "source_ip": event.get("source_ip", "N/A"),
                    "user_agent": event.get("user_agent", "N/A"),
                    "session_id": event.get("session_credential_from_console", "N/A"),
                    "Region": event.get("aws_region", "N/A"),
                    "geolocation": event.get("aws_region", "N/A"),
                    
                    "false_positive_info": {
                        "fp_id": event.get("id", "N/A"),
                        "result": analyze_result.get("is_false_positive", False),
                        "confidence": analyze_result.get("confidence", 0.0),
                        "reason": analyze_result.get("explanation", "N/A"),
                    },
                    
                    "Timeline": report.get("timeline", "N/A"),
                    "Mitre Mapping": report.get("mitre_mapping", "N/A"),
                    "Reason": report.get("reason", "N/A"),
                    "Threat Response": report.get("threat_response", "N/A"),
                    
                    "behavior": {
                        "unusual_time": is_unusual_time(event.get("event_time", "")),
                        "new_location": is_new_location(event.get("aws_region", "")),
                    },
                }

                report_link = generate_full_pdf(group_id, report_data)

                # DB에 저장
                db = SessionLocal()
                try:
                    # Severity를 enum으로 변환
                    severity_str = report_data.get("severity", "low").lower()
                    severity_map = {
                        "low": SeverityLevel.low,
                        "medium": SeverityLevel.medium,
                        "high": SeverityLevel.high
                    }
                    severity_enum = severity_map.get(severity_str, SeverityLevel.low)
                    
                    # 1. AgentResult 레코드 생성
                    agent_result = AgentResult(
                        id=event.get("id"),
                        severity=severity_enum,
                        timeline=report_data.get("Timeline", ""),
                        mitre_mapping=report_data.get("Mitre Mapping", ""),
                        report=report_link,
                        reason=report_data.get("Reason", ""),
                        response=report_data.get("Threat Response", ""),
                    )
                    
                    # AgentResult 저장 (upsert)
                    existing_result = db.query(AgentResult).filter(AgentResult.id == event.get("id")).first()
                    if existing_result:
                        # Update existing record
                        existing_result.severity = severity_enum
                        existing_result.timeline = report_data.get("Timeline", "")
                        existing_result.mitre_mapping = report_data.get("Mitre Mapping", "")
                        existing_result.report = report_link
                        existing_result.reason = report_data.get("Reason", "")
                        existing_result.response = report_data.get("Threat Response", "")
                    else:
                        # Insert new record
                        db.add(agent_result)
                    
                    # 2. AgentTotal 레코드 생성
                    def serialize_for_jsonb(data):
                        if isinstance(data, dict):
                            result = {}
                            for key, value in data.items():
                                if key == "messages":
                                    serialized_msgs = []
                                    for msg in value:
                                        if hasattr(msg, 'dict'):
                                            serialized_msgs.append(msg.dict())
                                        elif isinstance(msg, dict):
                                            serialized_msgs.append(msg)
                                        else:
                                            serialized_msgs.append({"content": str(msg)})
                                    result[key] = serialized_msgs
                                else:
                                    result[key] = value
                            return result
                        return data
                    
                    content_data = serialize_for_jsonb(supervisor_result)
                    
                    agent_total = AgentTotal(
                        id=event.get("id"),
                        content=content_data
                    )
                    
                    # AgentTotal 저장 (upsert)
                    existing_total = db.query(AgentTotal).filter(AgentTotal.id == event.get("id")).first()
                    if existing_total:
                        # Update existing record
                        existing_total.content = content_data
                    else:
                        # Insert new record
                        db.add(agent_total)
                    
                    db.commit()
                    print(f"✅ AgentResult and AgentTotal saved to DB for event_id: {event.get('id')}")

                    # 알림 전송 (최적화: group_id 파라미터 활용 및 불필요한 쿼리 제거)
                    try:
                        # 그룹의 알림 설정 가져오기
                        settings = db.query(Settings).filter(Settings.group_id == group_id).first()

                        # 알림이 활성화되어 있고, webhook URL이 설정되어 있으면 알림 전송
                        if settings and settings.notif_enabled and (settings.discord_webhook_url or settings.slack_webhook_url):
                            # event 객체에서 직접 event_time 파싱
                            event_time_str = event.get("event_time")
                            if event_time_str:
                                try:
                                    if isinstance(event_time_str, str):
                                        if '+' in event_time_str or 'Z' in event_time_str:
                                            event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                                        else:
                                            event_time = datetime.fromisoformat(event_time_str)
                                    else:
                                        event_time = event_time_str
                                except (ValueError, AttributeError):
                                    event_time = datetime.now()
                            else:
                                event_time = datetime.now()

                            NotificationService.send_notification(
                                discord_webhook_url=settings.discord_webhook_url,
                                slack_webhook_url=settings.slack_webhook_url,
                                event_time=event_time,
                                is_false_positive=analyze_result.get("is_false_positive", False),
                                reason=report_data.get("Reason", ""),
                                response=report_data.get("Threat Response", ""),
                                severity=severity_str
                            )
                            print(f"✅ 알림 전송 완료")
                    except Exception as notif_error:
                        print(f"⚠️ 알림 전송 실패 (계속 진행): {notif_error}")

                except Exception as e:
                    db.rollback()
                    print(f"❌ Failed to save to DB: {e}")
                finally:
                    db.close()

                return None
                    
            except json.JSONDecodeError as e:
                print(f"Failed to parse JSON: {e}")
                print("Content:", content)
                return None
        
        return None