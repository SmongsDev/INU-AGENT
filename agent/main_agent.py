import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network

from agent.Analyze_agent.Analyze import Analyze_agent
from agent.Supervisor_agent.supervisor_agent import Supervisor_agent
from report import generate_full_pdf

DEFAULT_BUSINESS_HOURS = (8, 18)  # 08:00~18:00
PRIVATE_NETWORKS = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("100.64.0.0/10"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
)


def _parse_iso_datetime(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return None
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            for date_format in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
                try:
                    return datetime.strptime(candidate, date_format).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
    return None


def _parse_hour(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        match = re.search(r"\d{1,2}", value)
        if match:
            return int(match.group(0))
    return None


def _resolve_business_hours(config):
    start_hour, end_hour = DEFAULT_BUSINESS_HOURS

    if isinstance(config, dict):
        start_candidate = _parse_hour(
            config.get("start") or config.get("from") or config.get("begin")
        )
        end_candidate = _parse_hour(config.get("end") or config.get("to") or config.get("until"))
    elif isinstance(config, (list, tuple)) and len(config) >= 2:
        start_candidate = _parse_hour(config[0])
        end_candidate = _parse_hour(config[1])
    elif isinstance(config, str):
        parts = re.findall(r"\d{1,2}", config)
        if len(parts) >= 2:
            start_candidate = int(parts[0])
            end_candidate = int(parts[1])
        else:
            start_candidate = end_candidate = None
    else:
        start_candidate = end_candidate = None

    if start_candidate is None or end_candidate is None or end_candidate <= start_candidate:
        return start_hour, end_hour
    return start_candidate, end_candidate


def _is_unusual_time(event_time_value, state):
    event_dt = _parse_iso_datetime(event_time_value)
    if not event_dt:
        return False

    start_hour, end_hour = _resolve_business_hours(state.get("business_hours"))

    if event_dt.weekday() >= 5:  # Weekend activity
        return True

    hour = event_dt.hour
    return hour < start_hour or hour >= end_hour


def _normalize_ip(ip_value):
    if not ip_value:
        return None

    ip_str = str(ip_value).strip()
    if not ip_str:
        return None

    if ip_str.startswith("[") and "]" in ip_str:
        ip_str = ip_str[1:ip_str.index("]")]
    if "%" in ip_str:
        ip_str = ip_str.split("%", 1)[0]
    if ip_str.count(":") == 1 and "." in ip_str:
        host, port = ip_str.split(":", 1)
        if port.isdigit():
            ip_str = host
    return ip_str or None


def _is_private_ip(ip_str):
    try:
        ip_obj = ip_address(ip_str)
    except ValueError:
        return False
    return any(ip_obj in network for network in PRIVATE_NETWORKS)


def _flatten_known_items(*items):
    flattened = []
    for item in items:
        if not item:
            continue
        if isinstance(item, (list, tuple, set)):
            flattened.extend(_flatten_known_items(*item))
        elif isinstance(item, dict):
            flattened.extend(_flatten_known_items(*item.values()))
        else:
            for token in re.split(r"[,\s]+", str(item)):
                token = token.strip()
                if token:
                    flattened.append(token)
    return flattened


def _extract_ipv4_prefix(ip_str):
    try:
        ip_obj = ip_address(ip_str)
    except ValueError:
        return None
    if ip_obj.version == 4:
        parts = ip_str.split(".")
        if len(parts) >= 2:
            return ".".join(parts[:2])
    return None


def _is_new_location(event, state):
    source_ip = _normalize_ip(
        event.get("source_ip")
        or event.get("sourceIPAddress")
        or event.get("source_ip_address")
    )
    aws_region = (event.get("aws_region") or event.get("awsRegion") or "").strip()

    behavior_baseline = state.get("behavior_baseline")

    known_ip_context = [
        state.get("known_source_ips"),
        state.get("known_ips"),
        state.get("known_ip_addresses"),
    ]

    if isinstance(behavior_baseline, dict):
        known_ip_context.append(behavior_baseline.get("known_source_ips"))

    known_ip_context.extend(
        [
            event.get("known_source_ips"),
            event.get("recent_source_ips"),
            event.get("previous_source_ips"),
            event.get("historical_source_ips"),
            event.get("ip_history"),
        ]
    )

    known_ips = {
        ip_item
        for ip_item in (
            _normalize_ip(token) for token in _flatten_known_items(*known_ip_context)
        )
        if ip_item
    }

    if source_ip:
        if source_ip in known_ips:
            return False

        source_prefix = _extract_ipv4_prefix(source_ip)
        known_prefixes = {
            prefix for prefix in (_extract_ipv4_prefix(ip_item) for ip_item in known_ips) if prefix
        }

        if known_prefixes and source_prefix in known_prefixes:
            return False

        if known_ips:
            return True

        return not _is_private_ip(source_ip)

    known_region_context = [
        state.get("known_regions"),
        state.get("preferred_regions"),
        state.get("allowed_regions"),
    ]

    if isinstance(behavior_baseline, dict):
        known_region_context.extend(
            [
                behavior_baseline.get("regions"),
                behavior_baseline.get("known_regions"),
                behavior_baseline.get("allowed_regions"),
            ]
        )

    known_region_context.extend(
        [
            event.get("known_regions"),
            event.get("recent_regions"),
            event.get("historical_regions"),
        ]
    )

    known_regions = {
        token.lower()
        for token in _flatten_known_items(*known_region_context)
        if isinstance(token, str) and token.strip()
    }

    if aws_region:
        aws_region_lower = aws_region.lower()
        if aws_region_lower in known_regions:
            return False
        if known_regions:
            return True

        home_region = state.get("home_region") or state.get("primary_region")
        if isinstance(home_region, str) and home_region.strip():
            return aws_region_lower != home_region.lower()

    return False

def agent(event: dict, state: dict):
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
                        "unusual_time": _is_unusual_time(event.get("event_time"), state),
                        "new_location": _is_new_location(event, state),
                    },
                }

                generate_full_pdf("accbe9c0-7ae8-4aa3-a0c7-9992e009f8cf", report_data)
                return None
                    
            except json.JSONDecodeError as e:
                print(f"Failed to parse JSON: {e}")
                print("Content:", content)
                return None
        
        return None
