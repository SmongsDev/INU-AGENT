from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import and_, func
from uuid import UUID
from collections import Counter

from app.db.models import Event, CloudTrail, MLLog, AgentResult
from app.schemas.chat import ThreatStats, CriticalThreat
from app.core.logger import get_logger

logger = get_logger(__name__)


class ChatService:
    """챗봇 서비스 - 위협 데이터 조회 및 통계 집계"""

    @staticmethod
    def fetch_threat_data(
        db: Session,
        group_id: UUID,
        start_date: datetime,
        end_date: datetime
    ) -> List[Dict]:
        """
        위협 데이터 조회 (날짜 필터링)

        Args:
            db: 데이터베이스 세션
            group_id: 그룹 ID
            start_date: 시작 날짜
            end_date: 종료 날짜

        Returns:
            위협 데이터 리스트
        """
        try:
            query = db.query(
                Event.id.label('event_id'),
                CloudTrail.event_name,
                CloudTrail.event_time,
                CloudTrail.source_ip,
                AgentResult.severity
            ).join(
                CloudTrail, Event.id == CloudTrail.id
            ).join(
                AgentResult, Event.id == AgentResult.id
            ).filter(
                and_(
                    Event.group_id == group_id,
                    CloudTrail.event_time >= start_date,
                    CloudTrail.event_time <= end_date,
                    AgentResult.severity.isnot(None)  # severity가 있는 것만 (Agent 분석 완료)
                )
            ).order_by(CloudTrail.event_time.desc()).limit(100)

            results = query.all()

            threat_data = []
            for row in results:
                threat_data.append({
                    'event_id': str(row.event_id),
                    'event_name': row.event_name,
                    'event_time': row.event_time,
                    'source_ip': str(row.source_ip) if row.source_ip else None,
                    'severity': row.severity.value if row.severity else 'low'  # Enum to string
                })

            return threat_data

        except Exception as e:
            logger.error(f"Error fetching threat data: {str(e)}")
            raise

    @staticmethod
    def aggregate_statistics(threat_data: List[Dict]) -> ThreatStats:
        """
        위협 데이터 통계 집계

        Args:
            threat_data: 위협 데이터 리스트

        Returns:
            ThreatStats 객체
        """
        if not threat_data:
            return ThreatStats(
                total_count=0,
                by_risk_level={'high': 0, 'medium': 0, 'low': 0},
                by_event_type={},
                top_events=[],
                critical_threats=[]
            )

        # 전체 건수
        total_count = len(threat_data)

        # 위험도별 분포
        severity_counter = Counter(item['severity'] for item in threat_data)
        by_risk_level = {
            'high': severity_counter.get('high', 0),
            'medium': severity_counter.get('medium', 0),
            'low': severity_counter.get('low', 0)
        }

        # 이벤트 타입별 건수
        event_type_counter = Counter(item['event_name'] for item in threat_data)
        by_event_type = dict(event_type_counter)

        # 상위 5개 이벤트
        top_events = [[name, count] for name, count in event_type_counter.most_common(5)]

        # 주요 고위험 위협 (HIGH 위험도 - confidence 정보가 없으므로 시간순)
        high_severity_threats = [
            item for item in threat_data
            if item['severity'] == 'high'
        ]

        critical_threats = []
        for threat in high_severity_threats[:10]:
            critical_threats.append(CriticalThreat(
                event_name=threat['event_name'],
                event_time=threat['event_time'].isoformat() if isinstance(threat['event_time'], datetime) else threat['event_time'],
                confidence=0.9,  # confidence 정보가 없으므로 기본값
                source_ip=threat['source_ip']
            ))

        return ThreatStats(
            total_count=total_count,
            by_risk_level=by_risk_level,
            by_event_type=by_event_type,
            top_events=top_events,
            critical_threats=critical_threats
        )
