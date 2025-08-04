import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
from app.schemas.cloudtrail import CloudTrailEvent
from app.core.logger import get_logger
from langgraph_flow.graph import process_security_event
from langgraph_flow.nodes.store import store_false_positive
from langgraph_flow.nodes.rag.document_converter import convert_cloudtrail_to_text

logger = get_logger(__name__)

class Tier1Filter:
    """
    Tier1 ML 데이터 필터링 클래스
    CloudTrail 이벤트를 분석하여 event_name, error_code 등을 기반으로 필터링
    """
    
    # 위험도가 높은 이벤트 패턴들
    HIGH_RISK_EVENTS = {
        "AssumeRole",
        "AssumeRoleWithSAML", 
        "AssumeRoleWithWebIdentity",
        "CreateUser",
        "DeleteUser",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "CreateRole",
        "DeleteRole",
        "PutBucketPolicy",
        "DeleteBucket",
        "CreateAccessKey",
        "DeleteAccessKey",
        "ConsoleLogin"
    }
    
    # 일반적으로 무시할 수 있는 읽기 전용 이벤트들
    LOW_RISK_EVENTS = {
        "DescribeInstances",
        "ListBuckets", 
        "GetBucketLocation",
        "GetObject",
        "HeadObject",
        "ListObjects",
        "DescribeSecurityGroups",
        "DescribeVpcs",
        "GetCallerIdentity"
    }
    
    # 오탐 가능성이 높은 에러 코드들
    FALSE_POSITIVE_ERROR_CODES = {
        "AccessDenied",
        "InvalidUserID.NotFound",
        "NoSuchBucket",
        "NoSuchKey",
        "TokenRefreshRequired"
    }
    
    def __init__(self, max_workers: int = 5):
        self.logger = logger
        self.max_workers = max_workers
    
    def filter_event(self, event: CloudTrailEvent) -> dict:
        """
        단일 CloudTrail 이벤트를 필터링하고 위험도 평가
        
        Args:
            event: CloudTrail 이벤트 객체
            
        Returns:
            dict: 필터링 결과 및 위험도 정보
        """
        result = {
            "event_id": event.event_id,
            "should_analyze": True,
            "risk_level": "medium",
            "filter_reason": None
        }
        
        try:
            # 1. 이벤트 이름 기반 필터링 - 저위험 읽기 전용은 분석 제외
            if event.event_name in self.LOW_RISK_EVENTS and event.read_only:
                result.update({
                    "should_analyze": False,
                    "risk_level": "low",
                    "filter_reason": "읽기 전용 저위험 이벤트"
                })
                return result
            
            # 2. 고위험 이벤트는 반드시 분석
            if event.event_name in self.HIGH_RISK_EVENTS:
                result.update({
                    "should_analyze": True,
                    "risk_level": "high",
                    "filter_reason": "고위험 이벤트 감지"
                })
            
            # 3. 에러 코드가 있는 경우 - 오탐 가능성이 높으나 재검증 필요
            if event.error_code in self.FALSE_POSITIVE_ERROR_CODES:
                result.update({
                    "should_analyze": True,
                    "risk_level": "low",
                    "filter_reason": "오탐 가능성 높은 에러 코드"
                })
            
            # 4. 성공한 관리 이벤트는 분석 필요
            if event.management_event and not event.error_code:
                result.update({
                    "should_analyze": True,
                    "risk_level": "high" if event.event_name in self.HIGH_RISK_EVENTS else "medium"
                })
            
            # 5. 콘솔 로그인 실패는 반드시 분석
            if event.event_name == "ConsoleLogin" and event.error_code:
                result.update({
                    "should_analyze": True,
                    "risk_level": "high",
                    "filter_reason": "콘솔 로그인 실패 감지"
                })
            
            self.logger.info(f"Event {event.event_id} filtered: {result}")
            
        except Exception as e:
            self.logger.error(f"Error filtering event {event.event_id}: {str(e)}")
            result.update({
                "should_analyze": True,
                "risk_level": "medium", 
                "filter_reason": "필터링 중 오류 발생"
            })
        
        return result
    
    def filter_events(self, events: List[CloudTrailEvent]) -> List[dict]:
        """
        여러 CloudTrail 이벤트를 배치로 필터링
        
        Args:
            events: CloudTrail 이벤트 리스트
            
        Returns:
            List[dict]: 필터링 결과 리스트
        """
        results = []
        
        for event in events:
            filter_result = self.filter_event(event)
            results.append(filter_result)
        
        # 통계 로깅
        total_events = len(results)
        high_risk_count = len([r for r in results if r["risk_level"] == "high"])
        low_risk_count = len([r for r in results if r["risk_level"] == "low"])
        filtered_out_count = len([r for r in results if not r["should_analyze"]])
        
        self.logger.info(f"Tier1 필터링 완료: 전체 {total_events}개, "
                        f"고위험 {high_risk_count}개, 저위험 {low_risk_count}개, "
                        f"필터링 제외 {filtered_out_count}개")
        
        return results
    
    def process_single_event(self, event: CloudTrailEvent):
        """
        단일 이벤트를 처리하고 적절한 함수로 라우팅 (리턴값 없음)
        
        Args:
            event: CloudTrail 이벤트 객체
        """
        # Tier1 필터링 실행
        filter_result = self.filter_event(event)
        
        try:
            if not filter_result["should_analyze"]:
                # 분석 불필요한 이벤트 처리
                # Tier2로 보내는 함수
                # is_false_positive 값도 바꿔야 할까?
                result = process_security_event(event)
                print(result)
            else:
                # 분석 필요한 이벤트 처리
                # DB 저장으로 마무리
                convert_cloudtrail_to_text(event)
                
        except Exception as e:
            self.logger.error(f"Error processing event {event.event_id}: {str(e)}")
    
    def process_events_batch(self, events: List[CloudTrailEvent]):
        """
        여러 이벤트를 병렬로 배치 처리 (리턴값 없음)
        
        Args:
            events: CloudTrail 이벤트 리스트
        """
        if not events:
            return
        
        processed_count = 0
        error_count = 0
        
        # ThreadPoolExecutor를 사용한 병렬 처리
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 모든 이벤트를 병렬로 제출
            future_to_event = {
                executor.submit(self.process_single_event, event): event 
                for event in events
            }
            
            # 완료된 순서대로 결과 수집
            for future in as_completed(future_to_event):
                event = future_to_event[future]
                try:
                    future.result()  # 예외가 있으면 여기서 발생
                    processed_count += 1
                except Exception as e:
                    self.logger.error(f"Error processing event {event.event_id}: {str(e)}")
                    event.is_false_positive = None  # 에러 시 None으로 설정
                    error_count += 1
        
        # 처리 완료 후 통계 계산
        tier2_analyzed = len([e for e in events if e.is_false_positive is not None and e.is_false_positive is not True])
        ignored_count = len([e for e in events if e.is_false_positive is True])
        error_final_count = len([e for e in events if e.is_false_positive is None])
        
        self.logger.info(f"병렬 배치 처리 완료: 전체 {len(events)}개, "
                        f"Tier2 분석 {tier2_analyzed}개, 분석 제외 {ignored_count}개, "
                        f"오류 {error_final_count}개 (최대 {self.max_workers} 워커 사용)")
    
    async def process_events_batch_async(self, events: List[CloudTrailEvent]):
        """
        여러 이벤트를 비동기로 배치 처리 (리턴값 없음)
        
        Args:
            events: CloudTrail 이벤트 리스트
        """
        if not events:
            return
        
        # 세마포어로 동시 실행 수 제한
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def process_with_semaphore(event: CloudTrailEvent):
            async with semaphore:
                # CPU 집약적 작업을 스레드 풀에서 실행
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self.process_single_event, event)
        
        # 모든 이벤트를 비동기로 처리
        tasks = [process_with_semaphore(event) for event in events]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 예외 처리
        error_count = 0
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Error processing event {events[i].event_id}: {str(result)}")
                events[i].is_false_positive = None  # 에러 시 None으로 설정
                error_count += 1
        
        # 처리 완료 후 통계 계산
        tier2_analyzed = len([e for e in events if e.is_false_positive is not None and e.is_false_positive is not True])
        ignored_count = len([e for e in events if e.is_false_positive is True])
        error_final_count = len([e for e in events if e.is_false_positive is None])
        
        self.logger.info(f"비동기 배치 처리 완료: 전체 {len(events)}개, "
                        f"Tier2 분석 {tier2_analyzed}개, 분석 제외 {ignored_count}개, "
                        f"오류 {error_final_count}개 (최대 {self.max_workers} 동시 실행)")