def convert_event_to_text(event_json: dict) -> str:
    """보안 이벤트 JSON을 텍스트로 변환합니다."""
    detection = event_json.get("detection_info", {})
    entities = event_json.get("entities", {})
    context = event_json.get("context", {})
    geo = context.get("geolocation", {})
    timing = context.get("timing", {})
    behavior = context.get("behavioral_flags", {})

    return (
        f"Event {event_json.get('event_id')} at {event_json.get('timestamp')}.\n"
        f"Rule: {detection.get('rule_name')} ({detection.get('rule_id')}), "
        f"Type: {detection.get('event_type')}, Severity: {detection.get('severity')}, "
        f"Confidence: {detection.get('confidence_score')}, Risk: {detection.get('initial_risk_score')}.\n"
        f"User: {entities.get('user_id')} from IP {entities.get('source_ip')}, "
        f"Agent: {entities.get('user_agent')}.\n"
        f"Location: {geo.get('country')} - {geo.get('region')} via {geo.get('isp')}.\n"
        f"Accessed during business hours: {timing.get('business_hours')}, Timezone: {timing.get('timezone')}.\n"
        f"Behavior flags - New Location: {behavior.get('new_location')}, "
        f"Unusual Time: {behavior.get('unusual_time')}, "
        f"High Frequency: {behavior.get('high_frequency')}."
    ) 