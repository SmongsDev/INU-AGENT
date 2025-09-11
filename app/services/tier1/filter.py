import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
from datetime import datetime
from app.schemas.cloudtrail import CloudTrailEvent
from ml.src.data.ml_result_saver import MLResultSaver
from app.core.logger import get_logger
from agent.graph import process_security_event
from agent.nodes.store import store_document, store_false_positive, update_false_positive_status
from agent.nodes.rag.document_converter import convert_cloudtrail_to_text

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
        self.ml_result_saver = MLResultSaver()
    
    def filter_event(self, event: CloudTrailEvent) -> dict:
        """
        단일 CloudTrail 이벤트를 필터링하고 위험도 평가
        
        Args:
            event: CloudTrail 이벤트 객체
            
        Returns:
            dict: 필터링 결과 및 위험도 정보
        """
        result = {
            "event_id": event.id,
            "should_analyze": False,  # 기본값: ML 정상 판단 확정
            "filter_reason": "ML 정상 판단 확정"
        }
        
        try:
            event_name = getattr(event, 'event_name', '')
            error_code = getattr(event, 'error_code', '')
            management_event = getattr(event, 'management_event', False)
            
            # 고위험 패턴 감지 시에만 Tier2로 전달
            if event_name in self.HIGH_RISK_EVENTS:
                result.update({
                    "should_analyze": True,
                    "filter_reason": "고위험 이벤트 감지 - Tier2 검증 필요"
                })
            elif event_name == "ConsoleLogin" and error_code:
                result.update({
                    "should_analyze": True,
                    "filter_reason": "콘솔 로그인 실패 감지 - Tier2 검증 필요"
                })
            elif management_event and not error_code and event_name in self.HIGH_RISK_EVENTS:
                result.update({
                    "should_analyze": True,
                    "filter_reason": "고위험 관리 이벤트 - Tier2 검증 필요"
                })
            # 그 외 모든 경우는 기본값 유지 (should_analyze=False, ML 판단 확정)
            
        except Exception as e:
            self.logger.error(f"Error filtering event {event.id}: {str(e)}")
            # 에러 발생 시에는 안전하게 Tier2로 전달
            result.update({
                "should_analyze": True,
                "filter_reason": "필터링 중 오류 발생 - 안전을 위해 Tier2 검증"
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
        filtered_out_count = len([r for r in results if not r["should_analyze"]])
        analyze_count = len([r for r in results if r["should_analyze"]])
        
        self.logger.info(f"Tier1 필터링 완료: 전체 {total_events}개, "
                        f"분석 필요 {analyze_count}개, 필터링 제외 {filtered_out_count}개")
        
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
                result = process_security_event(event)
                update_false_positive_status(event, False)
                print(result)
            else:
                # 분석 필요한 이벤트 처리
                # DB 저장으로 마무리
                event_summary = convert_cloudtrail_to_text(event)
                store_document(event_summary=event_summary, explanation=filter_result["filter_reason"], event_id=str(event.id))
                
        except Exception as e:
            self.logger.error(f"Error processing event {event.id}: {str(e)}")
    
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
                    self.logger.error(f"Error processing event {event.id}: {str(e)}")
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
    
    def process_ml_analysis_results(self, analysis_results: List[dict]):
        """
        ML이 정상으로 판단한 이벤트들에 대해 배치 처리로 추가 검증 필요성을 판단
        
        Args:
            analysis_results: ML이 정상으로 판단한 이벤트들의 분석 결과 리스트
        """
        if not analysis_results:
            self.logger.info("처리할 ML 분석 결과가 없습니다")
            return
        
        start_time = datetime.now()
        
        try:
            from app.services.filter_log_service import FilterLogService
            filter_log_service = FilterLogService()
            
            # 배치 처리를 위한 통계 변수들
            filter_log_data = []
            processed_count = 0
            threat_count = 0
            false_positive_count = 0
            error_count = 0
            
            # ThreadPoolExecutor를 사용한 병렬 필터링 처리
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # 모든 분석 결과를 병렬로 제출
                future_to_result = {
                    executor.submit(self._process_single_ml_result, result): result 
                    for result in analysis_results
                }
                
                # 완료된 순서대로 결과 수집
                for future in as_completed(future_to_result):
                    original_result = future_to_result[future]
                    try:
                        processing_result = future.result()
                        
                        if processing_result is None:
                            continue
                            
                        processed_count += 1
                        
                        # 통계 수집
                        if processing_result.get('is_threat', False):
                            threat_count += 1
                        
                        should_analyze = processing_result.get('should_analyze', True)
                        
                        if should_analyze:
                            # Tier2 Agent로 전달하여 재검증
                            print("검증")
                            # try:
                            #     event = original_result.get('event')
                            #     confidence = processing_result.get('confidence', 0.0)
                                
                            #     # 이미 CloudTrailEvent이므로 바로 전달
                            #     agent_result = process_security_event(event, confidence)
                                
                            #     # Agent 결과에 따른 처리 (필요시 추가 로직)
                            #     # agent_result['is_false_positive'] 값 활용 가능
                                
                            # except Exception as e:
                            #     # Tier2 Agent 오류는 중요하므로 로깅 유지
                            #     event_id = processing_result.get('event_id', 'Unknown')
                            #     self.logger.error(f"Tier2 Agent 검증 오류 (Event {event_id}): {e}")
                        else:
                            # ML 판단 확정 = 정상으로 최종 확정
                            false_positive_count += 1
                            filter_log_data.append(processing_result.get('filter_data'))
                            
                    except Exception as e:
                        # 개별 에러 로깅 제거 - 에러 카운트만 증가
                        error_count += 1
            
            # filter_log 테이블에 저장 (정상으로 확정된 경우만)
            tier2_count = processed_count - false_positive_count
            save_success_count = 0
            
            if filter_log_data:
                save_stats = filter_log_service.save_filter_results(filter_log_data)
                save_success_count = save_stats.get('success', 0)
            
            # 처리 완료 통계 로깅
            end_time = datetime.now()
            processing_time = (end_time - start_time).total_seconds()
            
            # 성능 통계 계산
            events_per_second = len(analysis_results) / processing_time if processing_time > 0 else 0
            
            self.logger.info(
                f"Tier1 배치완료: {len(analysis_results)}개→{processed_count}개처리 "
                f"({processing_time:.1f}초, {events_per_second:.0f}개/초) | "
                f"정상확정:{false_positive_count} Tier2필요:{tier2_count} 오류:{error_count} 저장:{save_success_count}"
            )
            
        except Exception as e:
            self.logger.error(f"ML 분석 결과 배치 처리 중 치명적 오류: {e}")
    
    def _process_single_ml_result(self, result: dict) -> Optional[dict]:
        """
        단일 ML 분석 결과를 처리하는 헬퍼 함수 (병렬 처리용)
        
        Args:
            result: 단일 ML 분석 결과
            
        Returns:
            Optional[dict]: 처리 결과 또는 None (오류 시)
        """
        try:
            event = result.get('event')
            ml_prediction = result.get('ml_prediction', {})
            
            if not event or not ml_prediction:
                return None
            
            # tier1 필터링 수행
            filter_result = self.filter_event(event)
            
            is_threat = ml_prediction.get('is_threat', False)
            confidence = ml_prediction.get('confidence', 0.0)
            event_id = str(event.id) if event.id else ''
            
            # 필터링 결과 판단
            should_analyze = filter_result.get('should_analyze', True)
            filter_reason = filter_result.get('filter_reason', 'Unknown')
            
            processing_result = {
                'event_id': event_id,
                'is_threat': is_threat,
                'confidence': confidence,
                'should_analyze': should_analyze,
                'filter_reason': filter_reason
            }
            
            if not should_analyze:
                # 정상으로 확정된 경우 filter_log 데이터 준비
                filter_data = {
                    "ml_log_id": event_id,  # ml_log의 id와 동일
                    "filter_result": {
                        "should_analyze": should_analyze,  # False
                        "filter_reason": filter_reason,
                        "ml_prediction": {
                            "is_threat": is_threat,
                            "confidence": confidence
                        },
                        "filter_timestamp": str(datetime.now())
                    }
                }
                processing_result['filter_data'] = filter_data
            
            return processing_result
            
        except Exception as e:
            # 개별 처리 오류는 로깅하지 않고 None 반환만
            return None