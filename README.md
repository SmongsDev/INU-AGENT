# 탐지 에이전트

이 프로젝트는 AWS GuardDuty, CloudTrail, CloudWatch 등 다양한 AWS 보안 이벤트 소스를 통합적으로 수집·분석·내보내기 위한 Python 기반 에이전트 프레임워크입니다.

## 주요 특징

- **다중 AWS 보안 소스 지원**: GuardDuty, CloudTrail, CloudWatch 이벤트 수집 및 분석
- **모듈화된 수집기 구조**: 각 서비스별 Collector 클래스 제공
- **이벤트 데이터 모델링**: dataclass 기반의 일관된 이벤트 모델
- **위험도/심각도 분석**: 이벤트별 위험도, 심각도, 위협 카테고리 자동 분류
- **필터링/통계/내보내기**: 다양한 기준의 필터, 통계 요약, JSON/CSV 내보내기 지원
- **Mock 기반 테스트**: AWS 환경 없이도 Mock 데이터로 단위/통합 테스트 가능
- **확장성**: 새로운 AWS 서비스 Collector 추가 용이

## 폴더 구조

```
agents/
  detect/
    collectors/         # 서비스별 수집기 (GuardDuty, CloudTrail 등)
    models/             # 이벤트 데이터 모델
    detect_agent.py     # 통합 탐지 에이전트
  report_agent.py
  respond_agent.py
  analyze_agent.py
app/
  main.py               # (예정) API/서비스 진입점
  services/
  core/
  api/
langgraph_flow/         # (예정) LangGraph 기반 워크플로우
tests/
  collector/            # 각 서비스별 수집기 테스트 (Mock 포함)
  data/                 # 테스트용 샘플 데이터
  test_graph.py
  test_agents.py
requirements.txt        # 의존성 목록
README.md
```

## 주요 모듈 설명

- **agents/detect/collectors/**  
  - `guardduty_collector.py`: GuardDuty 탐지 결과 수집/필터/내보내기  
  - `cloudtrail_collector.py`: CloudTrail 이벤트 수집/필터/내보내기  
  - `base_collector.py`: 모든 Collector의 추상 기반 클래스  
- **agents/detect/models/events.py**  
  - CloudTrail, GuardDuty, CloudWatch 등 이벤트 데이터 모델 정의  
  - 위험도/심각도/카테고리 등 분석 메서드 포함  
- **agents/detect/detect_agent.py**  
  - GuardDuty/CloudTrail 등 Collector를 통합 관리  
  - 탐지 실행, 결과 변환, 통계, 내보내기 등 통합 로직  
- **tests/**  
  - Mock 기반 단위/통합 테스트, 샘플 데이터, 시나리오 기반 검증  
  - `test_guardduty_mock.py`, `test_cloudtrail_mock.py` 등

## 설치 및 실행

1. **의존성 설치**
   ```bash
   pip install -r requirements.txt
   ```

2. **테스트 실행**
   ```bash
   # GuardDuty 모듈 종합 테스트
   python tests/collector/test_guardduty_mock.py

   # CloudTrail 수집기 Mock 테스트
   제작 중
   ```

3. **탐지 에이전트 실행**
   ```bash
   python agents/detect/detect_agent.py --region us-east-1 --hours 24 --sources guardduty cloudtrail --export-format json
   ```

   주요 옵션:
   - `--region`: AWS 리전 (기본: us-east-1)
   - `--hours`: 탐지 시간 범위(시간)
   - `--sources`: 사용할 소스(guardduty, cloudtrail, cloudwatch)
   - `--severity-min`: GuardDuty 최소 심각도
   - `--event-names`: CloudTrail 이벤트명 필터
   - `--continuous`: 연속 탐지 모드
