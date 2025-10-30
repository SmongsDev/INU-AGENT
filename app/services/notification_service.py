"""
Discord와 Slack 알림 서비스
agent_results 테이블에 새로운 데이터가 생성되면 알림을 전송합니다.
"""

import requests
import json
from datetime import datetime
from typing import Optional
from app.core.logger import get_logger

logger = get_logger(__name__)


class NotificationService:
    """Discord와 Slack 알림을 전송하는 서비스"""

    @staticmethod
    def send_discord_notification(
        webhook_url: str,
        event_time: datetime,
        is_false_positive: bool,
        reason: str,
        response: str,
        severity: str = None
    ) -> bool:
        """
        Discord로 알림 전송

        Args:
            webhook_url: Discord Webhook URL
            event_time: 이벤트 발생 시간
            is_false_positive: 오탐 여부
            reason: 분석 이유
            response: 대응 방안
            severity: 심각도

        Returns:
            전송 성공 여부
        """
        try:
            # 색상 결정 (오탐이면 초록색, 위협이면 심각도에 따라)
            if is_false_positive:
                color = 3066993  # 초록색
                status = "✅ 오탐 (False Positive)"
            else:
                status = "🚨 위협 탐지"
                if severity == "high":
                    color = 15158332  # 빨간색
                elif severity == "medium":
                    color = 16776960  # 노란색
                else:
                    color = 3447003  # 파란색

            payload = {
                "embeds": [
                    {
                        "title": "🔔 INU-AGENT 보안 알림",
                        "description": status,
                        "color": color,
                        "fields": [
                            {
                                "name": "📅 이벤트 발생 시간",
                                "value": event_time.strftime("%Y-%m-%d %H:%M:%S") if event_time else "N/A",
                                "inline": True
                            },
                            {
                                "name": "⚠️ 심각도",
                                "value": severity.upper() if severity else "N/A",
                                "inline": True
                            },
                            {
                                "name": "🔍 오탐 여부",
                                "value": "예 (False Positive)" if is_false_positive else "아니오 (True Positive)",
                                "inline": True
                            },
                            {
                                "name": "📝 분석 이유 (Reason)",
                                "value": reason[:1024] if reason else "N/A",
                                "inline": False
                            },
                            {
                                "name": "💡 대응 방안 (Response)",
                                "value": response[:1024] if response else "N/A",
                                "inline": False
                            }
                        ],
                        "footer": {
                            "text": "INU-AGENT Security Alert System"
                        },
                        "timestamp": datetime.now().isoformat()
                    }
                ]
            }

            response_obj = requests.post(
                webhook_url,
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'},
                timeout=10
            )

            if response_obj.status_code == 204:
                logger.info(f"Discord 알림 전송 성공")
                return True
            else:
                logger.error(f"Discord 알림 전송 실패: {response_obj.status_code} - {response_obj.text}")
                return False

        except Exception as e:
            logger.error(f"Discord 알림 전송 중 오류: {str(e)}")
            return False

    @staticmethod
    def send_slack_notification(
        webhook_url: str,
        event_time: datetime,
        is_false_positive: bool,
        reason: str,
        response: str,
        severity: str = None
    ) -> bool:
        """
        Slack으로 알림 전송

        Args:
            webhook_url: Slack Webhook URL
            event_time: 이벤트 발생 시간
            is_false_positive: 오탐 여부
            reason: 분석 이유
            response: 대응 방안
            severity: 심각도

        Returns:
            전송 성공 여부
        """
        try:
            # 상태 메시지
            if is_false_positive:
                status_emoji = "✅"
                status_text = "오탐 (False Positive)"
            else:
                status_emoji = "🚨"
                status_text = "위협 탐지"

            # 심각도 이모지
            severity_emoji = {
                "high": "🔴",
                "medium": "🟡",
                "low": "🔵"
            }.get(severity, "⚪")

            payload = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🔔 INU-AGENT 보안 알림"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*{status_emoji} 상태:* {status_text}"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*📅 이벤트 발생 시간:*\n{event_time.strftime('%Y-%m-%d %H:%M:%S') if event_time else 'N/A'}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*⚠️ 심각도:*\n{severity_emoji} {severity.upper() if severity else 'N/A'}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*🔍 오탐 여부:*\n{'예 (False Positive)' if is_false_positive else '아니오 (True Positive)'}"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*📝 분석 이유 (Reason):*\n```{reason[:2000] if reason else 'N/A'}```"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*💡 대응 방안 (Response):*\n```{response[:2000] if response else 'N/A'}```"
                        }
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"INU-AGENT Security Alert System | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                            }
                        ]
                    }
                ]
            }

            response_obj = requests.post(
                webhook_url,
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'},
                timeout=10
            )

            if response_obj.status_code == 200:
                logger.info(f"Slack 알림 전송 성공")
                return True
            else:
                logger.error(f"Slack 알림 전송 실패: {response_obj.status_code} - {response_obj.text}")
                return False

        except Exception as e:
            logger.error(f"Slack 알림 전송 중 오류: {str(e)}")
            return False

    @staticmethod
    def send_notification(
        discord_webhook_url: Optional[str],
        slack_webhook_url: Optional[str],
        event_time: datetime,
        is_false_positive: bool,
        reason: str,
        response: str,
        severity: str = None
    ) -> dict:
        """
        Discord와 Slack 알림을 모두 전송

        Args:
            discord_webhook_url: Discord Webhook URL (optional)
            slack_webhook_url: Slack Webhook URL (optional)
            event_time: 이벤트 발생 시간
            is_false_positive: 오탐 여부
            reason: 분석 이유
            response: 대응 방안
            severity: 심각도

        Returns:
            전송 결과 딕셔너리
        """
        results = {
            "discord": None,
            "slack": None
        }

        if discord_webhook_url:
            results["discord"] = NotificationService.send_discord_notification(
                webhook_url=discord_webhook_url,
                event_time=event_time,
                is_false_positive=is_false_positive,
                reason=reason,
                response=response,
                severity=severity
            )

        if slack_webhook_url:
            results["slack"] = NotificationService.send_slack_notification(
                webhook_url=slack_webhook_url,
                event_time=event_time,
                is_false_positive=is_false_positive,
                reason=reason,
                response=response,
                severity=severity
            )

        return results
