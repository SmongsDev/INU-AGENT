import os
import json
import re
from typing import Dict
from openai import AsyncOpenAI
from fastapi import HTTPException

from app.schemas.chat import ThreatStats
from app.core.logger import get_logger

logger = get_logger(__name__)


class OpenAIService:
    """OpenAI 서비스 - GPT를 사용한 날짜 추출 및 요약 생성 (비동기)"""

    def __init__(self):
        """OpenAI 클라이언트 초기화"""
        try:
            api_key = os.getenv('OPENAI_API_KEY')

            if not api_key:
                raise ValueError("OpenAI API key is missing")

            self.client = AsyncOpenAI(api_key=api_key)
            self.model = os.getenv('OPENAI_MODEL', 'gpt-4o-mini')  # 기본값: gpt-4o-mini (저렴)
        except Exception as e:
            raise

    async def extract_date_range(self, user_question: str) -> Dict[str, str]:
        """
        OpenAI를 사용해 자연어 질문에서 날짜 범위 추출 (비동기)

        Args:
            user_question: 사용자 질문

        Returns:
            {'start_date': 'YYYY-MM-DD', 'end_date': 'YYYY-MM-DD'}

        Raises:
            HTTPException: OpenAI API 호출 실패 시
        """
        from datetime import datetime

        today = datetime.now().strftime('%Y-%m-%d')
        weekday = datetime.now().strftime('%A')  # Monday, Tuesday, etc.

        prompt = f"""Today: {today} ({weekday})
Q: "{user_question}"

Rules:
최근/recent=7d ago, 오늘/today=today, 어제=yesterday, 그제=-2d
N일전/N일간=-Nd~today, 일주일/week=-7d~today
이번주=Mon~today, 저번주/지난주=lastMon~Sun
이번달=1st~today, 지난달=last month full
X월=full month, X월Y주차=week Y of month X
X월초=1-10, X월중순=11-20, X월말=21-end
Default=7d ago

Return JSON only: {{"start_date":"YYYY-MM-DD","end_date":"YYYY-MM-DD"}}
Max end_date: {today}"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=0.0,  # 일관된 결과를 위해 0으로 설정
                max_tokens=100,
                timeout=30.0  # 30초 타임아웃
            )

            response_text = response.choices[0].message.content.strip()

            # JSON 추출
            json_match = re.search(r'\{.*?\}', response_text, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
            else:
                raise ValueError("Failed to extract JSON from OpenAI response")

            date_range = json.loads(json_str)

            # 검증
            if 'start_date' not in date_range or 'end_date' not in date_range:
                raise ValueError("Invalid date range format from OpenAI")

            return date_range

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse OpenAI date response: {response_text}")
            raise HTTPException(
                status_code=400,
                detail=f"날짜 정보를 추출할 수 없습니다. 질문을 더 구체적으로 작성해주세요. (예: '최근 7일', '이번주', '10월 1일부터 10일까지')"
            )
        except Exception as e:
            logger.error(f"OpenAI date extraction error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"날짜 추출 중 오류가 발생했습니다: {str(e)}"
            )

    def create_summary_prompt(self, stats: ThreatStats, user_question: str, period: Dict[str, str]) -> str:
        """
        OpenAI에 전달할 프롬프트 생성

        Args:
            stats: 집계된 통계 데이터
            user_question: 사용자의 질문
            period: 조회 기간

        Returns:
            프롬프트 문자열
        """
        # 상위 5개 이벤트 포맷
        top_events_text = "\n".join([
            f"  {idx+1}. {event[0]}: {event[1]}건"
            for idx, event in enumerate(stats.top_events)
        ]) if stats.top_events else "  (없음)"

        # 주요 고위험 위협 포맷
        critical_threats_text = ""
        if stats.critical_threats:
            for idx, threat in enumerate(stats.critical_threats, 1):
                critical_threats_text += f"  {idx}. {threat.event_name}\n"
                critical_threats_text += f"     - 시간: {threat.event_time}\n"
                critical_threats_text += f"     - 신뢰도: {threat.confidence:.1%}\n"
                if threat.source_ip:
                    critical_threats_text += f"     - 소스 IP: {threat.source_ip}\n"
        else:
            critical_threats_text = "  (없음)"

        prompt = f"""Cloud security analyst. Concise Korean answer.

Period: {period['start']}~{period['end']}
Total: {stats.total_count} | H:{stats.by_risk_level.get('high', 0)} M:{stats.by_risk_level.get('medium', 0)} L:{stats.by_risk_level.get('low', 0)}

Top events:
{top_events_text}

Critical threats:
{critical_threats_text}

Q: "{user_question}"

Format (Korean, be brief):
## 답변
## 주요 위협 (top 3)
## 권장사항 (2-3 items)

Keep under 500 words."""

        return prompt

    async def generate_summary(self, stats: ThreatStats, user_question: str, period: Dict[str, str]) -> str:
        """
        위협 통계를 기반으로 AI 요약 생성 (비동기)

        Args:
            stats: 집계된 통계 데이터
            user_question: 사용자의 질문
            period: 조회 기간

        Returns:
            AI가 생성한 요약 텍스트
        """
        # 데이터가 없는 경우 간단한 메시지 반환 (OpenAI 호출 없이)
        if stats.total_count == 0:
            return f"""## 💬 질문에 대한 답변
"{user_question}"

조회 기간 ({period['start']} ~ {period['end']})에는 탐지된 보안 위협이 없습니다.

## 📊 전체 요약
해당 기간 동안 시스템에서 보안 위협이 탐지되지 않았습니다. 이는 긍정적인 신호이며, 보안 시스템이 정상적으로 운영되고 있음을 의미합니다.

## 💡 권장 사항
- 정기적인 보안 모니터링을 계속 유지하세요
- 보안 정책이 올바르게 적용되고 있는지 확인하세요
- 이상 징후가 발견되면 즉시 대응할 수 있도록 준비하세요"""

        # 프롬프트 생성 및 OpenAI 호출
        prompt = self.create_summary_prompt(stats, user_question, period)

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=800,  # AWS 환경에서 60초 이내 응답을 위해 축소
                timeout=40.0  # 40초 타임아웃
            )

            summary = response.choices[0].message.content.strip()
            return summary

        except Exception as e:
            logger.error(f"OpenAI API error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"AI 요약 생성 실패: {str(e)}"
            )
