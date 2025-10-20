import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
from datetime import datetime
from agent.Analyze_agent.Analyze import Analyze_agent
from ml.src.data.ml_result_saver import MLResultSaver
from app.core.logger import get_logger
from agent.Supervisor_agent.supervisor_agent import supervisor
from app.services.agent_state_builder import build_supervisor_state

logger = get_logger(__name__)

class Tier1Filter:
    """
    Tier1 ML 데이터 필터링 클래스
    CloudTrail 이벤트를 분석하여 event_name, error_code 등을 기반으로 필터링
    """
    
    # 위험도가 높은 이벤트 패턴들
    HIGH_RISK_EVENTS = {
        # 역할 및 권한 관련
        "AssumeRole",
        "AssumeRoleWithSAML",
        "AssumeRoleWithWebIdentity",
        "CreateRole",
        "DeleteRole",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "PutRolePolicy",
        "DeleteRolePolicy",

        # 사용자 및 그룹 관리
        "CreateUser",
        "DeleteUser",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "PutUserPolicy",
        "DeleteUserPolicy",
        "CreateGroup",
        "DeleteGroup",
        "AttachGroupPolicy",
        "DetachGroupPolicy",
        "AddUserToGroup",
        "RemoveUserFromGroup",

        # 액세스 키 관리
        "CreateAccessKey",
        "DeleteAccessKey",
        "UpdateAccessKey",

        # S3 보안 관련
        "PutBucketPolicy",
        "DeleteBucket",
        "PutBucketAcl",
        "PutObjectAcl",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",

        # 네트워크 보안
        "CreateSecurityGroup",
        "DeleteSecurityGroup",
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
        "CreateVpc",
        "DeleteVpc",
        "CreateInternetGateway",
        "AttachInternetGateway",

        # 인증 및 로그인
        "ConsoleLogin",
        "AssumeRoleFailure",
        "ConsoleLoginFailure",

        # 암호화 및 키 관리
        "CreateKey",
        "DeleteKey",
        "DisableKey",
        "EnableKey",
        "ScheduleKeyDeletion",
        "CancelKeyDeletion",
        "PutKeyPolicy",

        # 로깅 및 모니터링 우회 (가장 위험)
        "StopLogging",
        "DeleteTrail",
        "PutEventSelectors",
        "DeleteConfigRule",
        "StopConfigurationRecorder"
    }

    # 정상 운영에서 자주 발생하지만 모니터링이 필요한 이벤트들
    MEDIUM_RISK_EVENTS = {
        # 인스턴스 및 리소스 관리 (정상 운영에서 자주 발생)
        "RunInstances",
        "TerminateInstances",
        "CreateImage",
        "CreateSnapshot",
        "ModifyImageAttribute",
        "ModifySnapshotAttribute",

        # 데이터베이스 운영 (정상 운영에서 발생)
        "CreateDBCluster",
        "DeleteDBCluster",
        "ModifyDBCluster",
        "CreateDBInstance",
        "DeleteDBInstance",
        "ModifyDBInstance",

        # Lambda 운영 (CI/CD에서 자주 발생)
        "CreateFunction",
        "DeleteFunction",
        "UpdateFunctionCode",
        "UpdateFunctionConfiguration",
        "AddPermission",
        "RemovePermission",

        # S3 운영 작업
        "PutObject",
        "DeleteObject",
        "CreateBucket",

        # 일반적인 네트워킹 (정상 운영)
        "CreateRoute",
        "DeleteRoute",
        "CreateSubnet",
        "DeleteSubnet"
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
    
    def __init__(self, max_workers: int = 5, group_id: str = None):
        self.logger = logger
        self.max_workers = max_workers
        self.group_id = group_id
        self.ml_result_saver = MLResultSaver()
    

    def filter_event_dict(self, event_dict: dict) -> dict:
        """
        딕셔너리 형태의 이벤트를 필터링하고 위험도 평가

        Args:
            event_dict: 이벤트 딕셔너리

        Returns:
            dict: 필터링 결과 및 위험도 정보
        """
        result = {
            "event_id": event_dict.get('_event_id', ''),
            "should_analyze": False,  # 기본값: ML 정상 판단 확정
            "filter_reason": "ML 정상 판단 확정"
        }

        try:
            event_name = event_dict.get('event_name', '')
            error_code = event_dict.get('error_code', '')
            management_event = event_dict.get('management_event', False)

            # 고위험 패턴 감지 시에만 Tier2로 전달
            if event_name in self.HIGH_RISK_EVENTS:
                result.update({
                    "should_analyze": True,
                    "filter_reason": "고위험 이벤트 감지",
                    "risk_level": "high"
                })
            elif event_name == "ConsoleLogin" and error_code:
                result.update({
                    "should_analyze": True,
                    "filter_reason": "콘솔 로그인 실패 감지",
                    "risk_level": "high"
                })
            elif management_event and not error_code and event_name in self.HIGH_RISK_EVENTS:
                result.update({
                    "should_analyze": True,
                    "filter_reason": "고위험 관리 이벤트",
                    "risk_level": "high"
                })
            elif event_name in self.MEDIUM_RISK_EVENTS:
                # 중위험 이벤트는 시간대나 컨텍스트에 따라 분석 여부 결정
                should_analyze_medium = self._should_analyze_medium_risk_event(event_dict)
                if should_analyze_medium:
                    result.update({
                        "should_analyze": True,
                        "filter_reason": f"중위험 이벤트 의심 상황: {should_analyze_medium}",
                        "risk_level": "medium"
                    })
                else:
                    result.update({
                        "risk_level": "medium"
                    })
            # elif event_name in self.LOW_RISK_EVENTS:
            #     result.update({
            #         "risk_level": "low"
            #     })
            # 그 외 모든 경우는 기본값 유지 (should_analyze=False, ML 판단 확정)
            else:
                result.update({
                    "risk_level": "low"
                })

        except Exception as e:
            self.logger.error(f"Error filtering event dict {event_dict.get('_event_id', 'Unknown')}: {str(e)}")
            # 에러 발생 시에는 안전하게 Tier2로 전달
            result.update({
                "should_analyze": True,
                "filter_reason": "필터링 중 오류 발생",
                "risk_level": "unknown"
            })

        return result

    def _should_analyze_medium_risk_event(self, event_dict: dict) -> str:
        """
        중위험 이벤트에 대해 추가 분석이 필요한지 판단

        Args:
            event_dict: 이벤트 딕셔너리

        Returns:
            str: 분석이 필요한 이유 (빈 문자열이면 분석 불필요)
        """
        try:
            event_time = event_dict.get('event_time', '')
            user_identity = event_dict.get('user_identity', {})
            source_ip = event_dict.get('source_ip_address', '')
            event_name = event_dict.get('event_name', '')

            # 시간대 기반 분석 (업무 시간 외)
            if event_time:
                try:
                    from datetime import datetime
                    # ISO 형식 시간 파싱 시도
                    if 'T' in event_time:
                        dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                        hour = dt.hour

                        # 업무시간 외 (밤 10시 ~ 오전 6시) 활동
                        if hour >= 22 or hour <= 6:
                            return "업무시간 외 활동"

                        # 주말 활동 체크 (간단히 구현)
                        weekday = dt.weekday()
                        if weekday >= 5:  # 토요일(5), 일요일(6)
                            return "주말 활동"

                except:
                    pass

            # 의심스러운 IP 패턴 (간단한 체크)
            if source_ip:
                # 외부 IP에서의 운영 작업
                if not source_ip.startswith(('10.', '172.', '192.168.')):
                    return "외부 IP에서의 운영 작업"

            # 특정 사용자 타입 체크
            if user_identity:
                user_type = user_identity.get('type', '')
                user_name = user_identity.get('userName', '')

                # 루트 사용자의 운영 작업
                if user_type == 'Root':
                    return "루트 사용자 활동"

                # 임시 자격증명의 운영 작업
                if user_type == 'AssumedRole' and 'temp' in user_name.lower():
                    return "임시 자격증명 운영 작업"

            # 에러가 있는 중위험 이벤트
            error_code = event_dict.get('error_code', '')
            if error_code:
                return f"운영 작업 실패: {error_code}"

            return ""  # 분석 불필요

        except Exception as e:
            # 에러 발생 시 안전하게 분석 필요로 판단
            return "컨텍스트 분석 오류"

    def _run_supervisor_agent_sync(self, state: dict, event_id: str) -> None:
        """Supervisor Agent를 동기적으로 실행 (별도 스레드에서 호출용)"""
        try:
            supervisor_instance = supervisor(state)

            # 스트리밍 결과 수집
            agent_results = []
            for chunk in supervisor_instance.stream(state):
                agent_results.append(chunk)

            self.logger.info(f"Supervisor Agent 재검증 완료: Event {event_id}")

        except Exception as e:
            self.logger.error(f"Supervisor Agent 재검증 오류 (Event {event_id}): {e}", exc_info=True)

    async def _process_single_agent_call(self, original_result: dict, processing_result: dict) -> None:
        """단일 이벤트를 Supervisor Agent로 전달 (비동기)"""
        try:
            event_dict = original_result.get('event_dict')
            ml_prediction = original_result.get('ml_prediction', {})
            event_id = processing_result.get('event_id', 'Unknown')

            # State 생성 - 헬퍼 함수 사용
            state = build_supervisor_state(
                group_id=self.group_id,
                event_dict=event_dict,
                ml_prediction=ml_prediction
            )

            # # Supervisor Agent를 별도 스레드에서 실행 (이벤트 루프 블로킹 방지)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                self._run_supervisor_agent_sync,
                state,
                event_id
            )

            
            result = Analyze_agent().invoke({"event": event_dict, "retrive_cnt": 5})
            
        except Exception as e:
            # Tier2 Agent 오류는 중요하므로 로깅 유지
            event_id = processing_result.get('event_id', 'Unknown')
            self.logger.error(f"Supervisor Agent 재검증 오류 (Event {event_id}): {e}", exc_info=True)

    async def process_ml_analysis_results(self, analysis_results: List[dict]):
        """
        ML이 정상으로 판단한 이벤트들에 대해 배치 처리로 추가 검증 필요성을 판단 (비동기)

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

            # 동기 필터링을 별도 스레드에서 실행
            loop = asyncio.get_event_loop()
            processing_results = await loop.run_in_executor(
                None,
                lambda: [self._process_single_ml_result(result) for result in analysis_results]
            )

            # Supervisor Agent 호출이 필요한 이벤트들 수집
            agent_tasks = []

            for original_result, processing_result in zip(analysis_results, processing_results):
                if processing_result is None:
                    continue

                processed_count += 1

                # 통계 수집
                if processing_result.get('is_threat', False):
                    threat_count += 1

                should_analyze = processing_result.get('should_analyze', True)

                if should_analyze:
                    # Tier2 Agent로 전달하여 재검증 - Supervisor Agent 사용
                    filter_log_data.append(processing_result.get('filter_data'))

                    # 비동기 Agent 호출 태스크 추가
                    # agent_tasks.append(self._process_single_agent_call(original_result, processing_result))
                else:
                    # ML 판단 확정 = 정상으로 최종 확정
                    false_positive_count += 1
                    filter_log_data.append(processing_result.get('filter_data'))

            # 모든 Supervisor Agent 호출을 병렬로 실행
            # if agent_tasks:
            #     await asyncio.gather(*agent_tasks, return_exceptions=True)

            # filter_log 테이블에 저장 (정상으로 확정된 경우만)
            tier2_count = processed_count - false_positive_count
            save_success_count = 0

            if filter_log_data:
                save_stats = await loop.run_in_executor(
                    None,
                    filter_log_service.save_filter_results,
                    filter_log_data
                )
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
            event_dict = result.get('event_dict')
            ml_prediction = result.get('ml_prediction', {})

            if not event_dict or not ml_prediction:
                return None

            # 딕셔너리 기반으로 필터링 수행
            filter_result = self.filter_event_dict(event_dict)
            
            is_threat = ml_prediction.get('is_threat', False)
            confidence = ml_prediction.get('confidence', 0.0)
            event_id = event_dict.get('_event_id', '')
            
            # 필터링 결과 판단
            should_analyze = filter_result.get('should_analyze', True)
            filter_reason = filter_result.get('filter_reason', 'Unknown')
            risk_level = filter_result.get('risk_level', 'unknown')

            processing_result = {
                'event_id': event_id,
                'is_threat': is_threat,
                'confidence': confidence,
                'should_analyze': should_analyze,
                'filter_reason': filter_reason,
                'risk_level': risk_level
            }
            # 다시 되돌릴 예정
            # if not should_analyze:
            # 정상으로 확정된 경우 filter_log 데이터 준비
            filter_data = {
                "ml_log_id": event_id,  # ml_log의 id와 동일
                "filter_result": {
                    "should_analyze": should_analyze,  # False
                    "filter_reason": filter_reason,
                    "risk_level": risk_level,
                    "ml_prediction": {
                        "is_threat": is_threat,
                        "confidence": confidence
                    },
                    "filter_timestamp": str(datetime.now())
                },
                "is_threat": is_threat  # False (ML이 정상으로 판단)
            }
            processing_result['filter_data'] = filter_data
            
            return processing_result
            
        except Exception as e:
            # 개별 처리 오류는 로깅하지 않고 None 반환만
            return None