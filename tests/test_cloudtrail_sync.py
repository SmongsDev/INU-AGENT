import pytest
import asyncio
from datetime import datetime, timezone
from app.services.data_sync_service import DataSyncService
from app.schemas.cloudtrail import CloudTrailEvent
from langgraph_flow.nodes.rag.document_converter import convert_cloudtrail_to_text
from langgraph_flow.graph import process_security_event

@pytest.mark.asyncio
async def test_fetch_and_convert_cloudtrail_events():
    """CloudTrail 이벤트 조회 및 텍스트 변환 테스트"""
    
    # DataSyncService 인스턴스 생성
    service = DataSyncService()
    
    # 이벤트 조회
    events = await service.fetch_new_data("cloudtrail")
    
    print("\n=== CloudTrail 이벤트 목록 ===")
    
    if not events:
        print("조회된 이벤트가 없습니다.")
        return
        
    print(f"\n총 {len(events)}개의 이벤트를 가져왔습니다.")
    
    for idx, event in enumerate(events, 1):
        result = process_security_event(event)
        print(result)
        print("-" * 80)

@pytest.mark.asyncio
async def test_continuous_sync_and_convert():
    """5분 동안 연속적으로 이벤트를 조회하고 변환하는 테스트"""
    
    service = DataSyncService()
    interval_minutes = 1  # 테스트를 위해 1분으로 설정
    total_runtime_minutes = 2
    cycles = total_runtime_minutes
    
    print(f"\n=== {total_runtime_minutes}분 동안 {interval_minutes}분 간격으로 이벤트 조회 ===")
    
    for cycle in range(cycles):
        print(f"\n[동기화 사이클 {cycle + 1}/{cycles}]")
        print(f"시작 시간: {datetime.now(timezone.utc).isoformat()}")
        
        events = await service.fetch_new_data("cloudtrail")
        
        if events:
            print(f"{len(events)}개의 새로운 이벤트를 발견했습니다.")
            for idx, event in enumerate(events, 1):
                print(f"\n이벤트 {idx}:")
                
                print("-" * 50)
        else:
            print("새로운 이벤트가 없습니다.")
            
        if cycle < cycles - 1:  # 마지막 사이클이 아닌 경우에만 대기
            print(f"{interval_minutes}분 대기 중...")
            await asyncio.sleep(interval_minutes * 60)

if __name__ == "__main__":
    # 단일 조회 테스트 실행
    # asyncio.run(test_fetch_and_convert_cloudtrail_events())
    
    # 연속 조회 테스트 실행
    print("\n연속 조회 테스트를 시작합니다...")
    asyncio.run(test_continuous_sync_and_convert()) 