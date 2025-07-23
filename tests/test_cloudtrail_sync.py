import pytest
import asyncio
from datetime import datetime, timezone
from app.services.data_sync_service import DataSyncService
from app.schemas.cloudtrail import CloudTrailEvent

@pytest.mark.asyncio
async def test_fetch_cloudtrail_events():
    """CloudTrail 이벤트 조회 테스트"""
    
    # DataSyncService 인스턴스 생성
    service = DataSyncService()
    
    # 이벤트 조회
    events = await service.fetch_new_data("cloudtrail")
    
    print("\n=== CloudTrail 이벤트 목록 ===")
    
    if not events:
        print("조회된 이벤트가 없습니다.")
        return
        
    for idx, event in enumerate(events, 1):
        print(f"\n[이벤트 {idx}]")
        print(f"ID: {event.id}")
        print(f"Event ID: {event.event_id}")
        print(f"Event Time: {event.event_time}")
        print(f"Event Source: {event.event_source}")
        print(f"Event Name: {event.event_name}")
        
        if event.aws_region:
            print(f"Region: {event.aws_region}")
            
        if event.user_identity:
            print("User Identity:")
            print(f"  Type: {event.user_identity.get('type', 'N/A')}")
            print(f"  Principal ID: {event.user_identity.get('principalId', 'N/A')}")
            print(f"  ARN: {event.user_identity.get('arn', 'N/A')}")
            
        if event.request_parameters:
            print("\nRequest Parameters:")
            for key, value in event.request_parameters.items():
                print(f"  {key}: {value}")
                
        if event.error_code:
            print(f"\nError: {event.error_code} - {event.error_message}")
            
        print("-" * 50)

if __name__ == "__main__":
    # 비동기 테스트 실행
    asyncio.run(test_fetch_cloudtrail_events()) 