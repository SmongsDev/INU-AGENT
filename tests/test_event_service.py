import asyncio
from app.services.events_service import EventService

async def test_event_monitoring():
    # 테스트할 group_id 설정
    group_id = "accbe9c0-7ae8-4aa3-a0c7-9992e009f8cf"
    
    print("\n=== 이벤트 모니터링 테스트 시작 ===")
    
    try:
        # EventService 인스턴스 생성
        event_service = EventService(group_id=group_id)
        
        print("1. 새로운 이벤트 조회 중...")
        # 새로운 이벤트 조회 테스트
        events = await event_service.fetch_new_events()
        
        print(f"조회된 이벤트 수: {len(events)}")
        
        # 처음 5개 이벤트 상세 정보 출력
        for event in events[:5]:
            print(f"\n이벤트 정보:")
            print(f"- ID: {event.id}")
            print(f"- 그룹 ID: {event.group_id}")
            print(f"- 소스: {event.source_product}")
            print(f"- 소스 IP: {event.source_ip}")
            print(f"- 생성 시간: {event.created_at}")
        
        print("\n2. 모니터링 시작 (10초 동안 실행)...")
        # 모니터링 태스크 생성
        monitoring_task = asyncio.create_task(
            event_service.start_monitoring(interval_minutes=1/6)  # 10초 간격으로 설정
        )
        
        # 10초 동안 실행
        await asyncio.sleep(10)
        
        # 태스크 취소
        monitoring_task.cancel()
        try:
            await monitoring_task
        except asyncio.CancelledError:
            print("모니터링 태스크가 정상적으로 종료되었습니다.")
            
    except Exception as e:
        print(f"테스트 중 오류 발생: {str(e)}")
    
    print("\n=== 이벤트 모니터링 테스트 종료 ===")

if __name__ == "__main__":
    asyncio.run(test_event_monitoring())
