import json
import re
from datetime import datetime

from agent.Analyze_agent.Analyze import Analyze_agent
from agent.Supervisor_agent.supervisor_agent import Supervisor_agent
from report import generate_full_pdf


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

def agent(event: dict, state: dict,):
    analyze_agent = Analyze_agent()
    analyze_result = analyze_agent.invoke({"event": event, "retrive_cnt": 5})

    is_false_positive = analyze_result.get("is_false_positive")

    if not is_false_positive:
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
                    print("Could not find valid JSON with 'severity' field in supervisor's response.")
                    print("Content:", content[:500])  # Print first 500 chars for debugging
                    return None
                
                report = json.loads(json_str)

                # Build detailed report_data dict
                report_data = {
                    "severity": report.get("severity", "N/A").lower(),
                    "accuracy": report.get("accuracy", 0.0),
                    "event_id": event.get("event_id", "N/A"),
                    "timestamp": event.get("event_time", "N/A"),
                    "source": event.get("event_source", "N/A"),
                    "event_name": event.get("event_name", "N/A"),
                    "user_arn": event.get("user_identity", "N/A"),
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
                    
                    "behavior": {
                        "unusual_time": is_unusual_time(event.get("event_time", "")),
                        "new_location": is_new_location(event.get("aws_region", "")),
                    },
                }

                generate_full_pdf("accbe9c0-7ae8-4aa3-a0c7-9992e009f8cf", report_data)
                return None
                    
            except json.JSONDecodeError as e:
                print(f"Failed to parse JSON: {e}")
                print("Content:", content)
                return None
        
        return None

