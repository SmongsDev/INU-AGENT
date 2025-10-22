"""
Supervisor Agent State Builder

Supervisor Agent에 전달할 state를 생성하는 유틸리티 모듈
DB에서 설정을 로드하고 일관된 state 구조를 제공
"""

from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import Meta_Data
from app.core.logger import get_logger
import uuid

logger = get_logger(__name__)


class AgentStateBuilder:
    """Supervisor Agent State 생성 빌더 클래스"""

    # 기본 설정값 (DB에서 로드 실패 시 사용)
    DEFAULT_CONFIG = {
        "sup_model": "gpt-4.1",
        "sql_model": "gpt-4.1",
        "rag_model": "gpt-4.1",
        "retrive_cnt": 5,
        "report_option": {
            "timeline": True,
            "mapping": True,
        }
    }

    def __init__(self, group_id: str, db: Optional[Session] = None):
        """
        Args:
            group_id: 그룹 ID (UUID 문자열)
            db: SQLAlchemy 세션 (선택적, 없으면 자동 생성)
        """
        self.group_id = group_id
        self._db = db
        self._config_cache = None

    def _get_db_session(self) -> Session:
        """DB 세션을 가져오거나 생성"""
        if self._db is not None:
            return self._db
        return next(get_db())

    def _load_agent_config(self) -> Dict[str, Any]:
        """
        DB에서 agent 설정을 로드

        Returns:
            agent_flow 설정 딕셔너리
        """
        if self._config_cache is not None:
            return self._config_cache

        try:
            db = self._get_db_session()

            # UUID 문자열을 UUID 객체로 변환
            try:
                group_uuid = uuid.UUID(self.group_id)
            except (ValueError, AttributeError):
                logger.warning(f"잘못된 group_id 형식: {self.group_id}. 기본 설정 사용")
                self._config_cache = self.DEFAULT_CONFIG.copy()
                return self._config_cache

            # meta_data 테이블에서 agent_flow 조회
            meta_data = db.query(Meta_Data).filter(
                Meta_Data.group_id == group_uuid
            ).first()

            if meta_data and meta_data.agent_flow:
                logger.info(f"Group {self.group_id}: DB에서 agent 설정 로드 성공")
                self._config_cache = meta_data.agent_flow
                return self._config_cache
            else:
                logger.warning(f"Group {self.group_id}: agent_flow가 없습니다. 기본 설정 사용")
                self._config_cache = self.DEFAULT_CONFIG.copy()
                return self._config_cache

        except Exception as e:
            logger.error(f"Agent 설정 로드 실패: {e}. 기본 설정 사용", exc_info=True)
            self._config_cache = self.DEFAULT_CONFIG.copy()
            return self._config_cache

    def build_state(
        self,
        event: Dict[str, Any],
        ml_prediction: Optional[Dict[str, Any]] = None,
        messages: Optional[List[Dict[str, str]]] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Supervisor Agent에 전달할 state를 생성

        Args:
            event: 이벤트 데이터 딕셔너리
            ml_prediction: ML 분석 결과 (선택적)
            messages: 초기 메시지 리스트 (선택적)
            additional_context: 추가 컨텍스트 정보 (선택적)

        Returns:
            Supervisor Agent state 딕셔너리
        """
        # DB에서 설정 로드
        config = self._load_agent_config()

        # 기본 state 구조 생성
        state = {
            "messages": messages if messages is not None else [],
            "sup_model": config.get("sup_model", "gpt-4.1"),
            "sql_model": config.get("sql_model", "gpt-4.1"),
            "rag_model": config.get("rag_model", "gpt-4.1"),
            "retrive_cnt": config.get("retrive_cnt", 5),
            "report_option": config.get("report_option", {
                "timeline": True,
                "mapping": True,
            }),
            "event": event,
        }

        # ML 분석 결과 추가
        if ml_prediction:
            state["ml_analysis_result"] = {
                "is_threat": ml_prediction.get("is_threat", False),
                "confidence": ml_prediction.get("confidence", 0.0),
                "prediction_details": ml_prediction.get("prediction_details", {})
            }

        # 추가 컨텍스트 정보 병합
        if additional_context:
            state.update(additional_context)

        return state


def build_supervisor_state(
    group_id: str,
    event: Dict[str, Any],
    ml_prediction: Optional[Dict[str, Any]] = None,
    messages: Optional[List[Dict[str, str]]] = None,
    additional_context: Optional[Dict[str, Any]] = None,
    db: Optional[Session] = None
) -> Dict[str, Any]:
    """
    Supervisor Agent state 생성을 위한 편의 함수

    Args:
        group_id: 그룹 ID (UUID 문자열)
        event: 이벤트 데이터 딕셔너리
        ml_prediction: ML 분석 결과 (선택적)
        messages: 초기 메시지 리스트 (선택적)
        additional_context: 추가 컨텍스트 정보 (선택적)
        db: SQLAlchemy 세션 (선택적)

    Returns:
        Supervisor Agent state 딕셔너리

    Example:
        >>> state = build_supervisor_state(
        ...     group_id="550e8400-e29b-41d4-a716-446655440000",
        ...     event={"event_name": "CreateUser", ...},
        ...     ml_prediction={"is_threat": True, "confidence": 0.95}
        ... )
    """
    builder = AgentStateBuilder(group_id=group_id, db=db)
    return builder.build_state(
        event=event,
        ml_prediction=ml_prediction,
        messages=messages,
        additional_context=additional_context
    )
