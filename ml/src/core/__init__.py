"""
Core ML 모델 및 훈련 모듈

ML 모델의 핵심 로직과 훈련 관련 기능을 제공합니다.
"""

from .cloudtrail_threat_detector import CloudTrailThreatDetector

__all__ = ["CloudTrailThreatDetector"]