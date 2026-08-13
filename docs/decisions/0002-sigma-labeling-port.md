# ADR-0002: ML 라벨링을 홈메이드 규칙에서 SigmaHQ 룰로 교체

- **날짜**: 2026-08-13 (실험 및 이식)
- **상태**: 결정됨 (부분 적용 — 특성 축 분리는 미완, §6 참고)
- **관련 저장소**: INU-AGENT (근거 실험은 INU-ML)

## 1. 배경 (Context) — 어떤 문제를 어떻게 발견했나

INU-ML에서 라벨 누수를 추적한 결과 세 개의 ADR이 나왔다.

- [INU-ML ADR-0001](../../../INU-ML/docs/decisions/0001-ml-label-leakage.md): 라벨 규칙이 참조하는
  필드를 특성에서 빼는 것만으로는 누수를 끊을 수 없다.
- [INU-ML ADR-0002](../../../INU-ML/docs/decisions/0002-sigma-rule-labeling.md): 홈메이드 라벨 규칙
  자체를 폐기하고 SigmaHQ 공개 룰로 교체. 단, **라벨 소스 교체와 특성 축 분리는 별개 작업**이며
  둘 다 해야 한다.
- [INU-ML ADR-0003](../../../INU-ML/docs/decisions/0003-v2-score-validity.md): 보고 수치는 분할
  방식과 룰 편중에 크게 좌우된다.

그런데 이 결론들이 **실제 서빙 경로에는 하나도 도달하지 않은 상태**였다.

- 발견 계기: INU-ML의 이관 작업 후 교차 저장소 영향을 점검하다 확인
- `INU-AGENT/ml/` 은 INU-ML을 import하지 않는 **독립 복제본**이다. 그래서 INU-ML의 변경이
  런타임을 깨뜨리지는 않았지만, 구현이 두 갈래로 갈라져 있었다.
- `app/services/ml_analysis_service.py`가 `ml/models/cloudTrail_v2.pkl`을 로드해 FastAPI로
  서빙한다. 즉 문서에는 "라벨 누수를 찾아 고쳤다"고 적혀 있는데 동작하는 시스템은 구 라벨
  체계로 돌고 있었다.

### AGENT 복제본은 단순 구버전이 아니었다

794행으로 INU-ML(374행)보다 크고, INU-ML에 없는 것들을 갖고 있다.

- `_extract_sequence_features`: 5분/1분 윈도우 시퀀스 특성
- `_check_definite_threat`: 예측 시 룰 오버라이드
- `predict_batch_with_confidence`, DB 로더, 결과 저장기 등 운영 연동

그리고 **시퀀스 특성이 누수 없는 형태로 구현되어 있었다** — `previous_events = logs_data[max(0, idx-100):idx]`
로 현재 이벤트를 제외한다. INU-ML의 v2 행동 특성과 같은 원리에 독립적으로 도달한 셈이다.

`THREAT_TOOLS`도 `curl`/`boto3`/`aws-cli` 같은 정상 자동화 도구를 이미 제외하도록 튜닝되어
있었다. INU-ML ADR-0001/0002가 지적한 "위협 비율 95.2%" 문제는 **AGENT에는 해당하지 않는다.**

### 그런데 그 시퀀스 특성을 라벨에도 쓰고 있었다

구 `_create_rule_based_labels`의 규칙 6:

```python
if features.get('has_stratus_in_1min') and features.get('burst_detected'):
    is_threat = True
if features.get('error_rate_5min', 0.0) > 0.5 and features.get('unique_api_count_5min', 0) > 10:
    is_threat = True
if features.get('user_activity_spike') and features['is_high_risk_action']:
    is_threat = True
```

이 다섯 필드는 **모델 특성으로도 그대로 들어간다**. 라벨과 특성이 같은 축을 넘어 동일 필드를
공유하는 상태다. INU-ML이 겪은 어떤 조건보다 직접적인 누수다.

규칙 1~5는 홈메이드 규칙을 "완화/강화"로 튜닝한 버전인데, 이는 INU-ML ADR-0002에서 A안으로
검토했다가 **기각한 경로**다. 기각 사유는 성능이 아니라 "우리가 기준을 만들고 우리가 채점하는
구조에서는 같은 실패가 반복된다"는 것이었다.

### 실측 (flaws.cloud, 시간순 연속 30,000건)

| 라벨 소스 | 위협 판정 | 비율 |
|---|---:|---:|
| AGENT 홈메이드 규칙 (시퀀스 규칙 6 포함) | 4,036 | 13.45% |
| AGENT 홈메이드 규칙 (규칙 1~5만) | 3,673 | 12.24% |
| Sigma 룰 10종 | 12,124 | 40.41% |

두 라벨의 관계:

| 구분 | 건수 |
|---|---:|
| 둘 다 위협 | **58** |
| AGENT만 위협 | 3,978 |
| Sigma만 위협 | 12,066 |
| 둘 다 정상 | 13,898 |

**교집합이 58건뿐이다.** 두 라벨은 사실상 완전히 다른 것을 측정하고 있었다.

AGENT 양성의 정체를 규칙별로 분해하면:

| 규칙 | 발화 |
|---|---:|
| 규칙 4 (프로그래매틱 + 고위험 액션 + 외부 IP) | 3,670 |
| 규칙 5 (의심 지표 4개 이상) | 79 |
| 규칙 2 (의심 리소스명) | 3 |
| 규칙 1 (Red Team 도구) | **0** |

양성의 91%가 `AssumeRole`(3,610건) 하나다. 그리고 **규칙 1은 한 번도 발화하지 않았다** —
튜닝된 `THREAT_TOOLS` 목록에 해당하는 도구가 이 데이터에 없기 때문이다. 그런데
`_check_definite_threat`는 바로 이 규칙 1을 근거로 confidence 0.99를 확정하고 ML을
건너뛰는 경로였다. 즉 **오버라이드 경로의 주력 규칙이 실데이터에서 무력했다.**

## 2. 검토한 대안들 (Options Considered)

| 옵션 | 설명 | 장점 | 단점 |
|---|---|---|---|
| A. 공유 패키지로 분리 | 두 구현의 장점을 합쳐 단일 패키지로 뽑고 양쪽이 import | 복제본 소멸, 재발 방지 | 저장소 경계·배포 방식 변경. 작업량 큼 |
| B. (선택) AGENT에 Sigma 라벨만 이식 | `_create_rule_based_labels`를 Sigma 라벨러로 교체, 규칙 6 제거 | 변경 범위가 작고 가장 큰 결함을 즉시 제거. AGENT의 시퀀스 특성·운영 연동을 그대로 보존 | 복제본이 남아 다시 갈라질 수 있음 |
| C. 진단만 하고 보류 | 오탐률·누수 규모를 측정해 기록만 | 위험 없음 | 서빙 경로가 깨진 채로 유지됨 |

## 3. 실험 설계 (Experiment)

flaws.cloud 공개 CloudTrail 로그를 **시간순 연속 구간**으로 사용한다(시퀀스 특성이 이벤트
인접성을 전제하므로 무작위 표본을 쓰면 의미가 왜곡된다).

```bash
# 라벨 비교 (이식 전)
# AGENT 탐지기와 INU-ML sigma_labeler를 같은 이벤트 집합에 적용해 교집합/차집합 산출

# 이식 후 누수 확인
# 동일 구간 30,000건으로 train() 실행, 전부-위협 베이스라인 대비 F1과 특성 중요도 확인
```

측정 지표는 F1과 **전부-위협 다수클래스 베이스라인 F1**을 함께 본다. 구간마다 위협 비율이
달라 F1 절대값끼리는 비교할 수 없기 때문이다.

## 4. 결과 (Results)

### 4.1 이식은 동작한다

- Sigma 룰 10종 로드, `_create_rule_based_labels` 제거 확인
- `_check_definite_threat`가 Sigma 매칭 기반으로 동작:
  - `StopLogging` → `(True, 0.9, "Sigma rule matched: AWS CloudTrail Important Change [medium] (attack.defense-impairment, attack.t1685.002)")`
  - 일반 `GetObject` → `(False, 0.0, "")`
- `train()` 정상 완료
- `ml/test_integration.py` 4개 중 2개 통과. **실패 2건은 이 변경과 무관하다** —
  `sqlalchemy` 미설치 때문이며, 변경 전(`git stash`)에도 동일하게 2/4였다.

### 4.2 라벨만 바꿔서는 누수가 사라지지 않는다 (INU-ML ADR-0002 §4.3 재현)

시간순 연속 30,000건, Sigma 위협 비율 24.97%:

| 지표 | 값 |
|---|---:|
| 전부-위협 베이스라인 F1 | 0.3996 |
| 교차검증 F1 | **0.9104** |
| 테스트셋 위협 클래스 Precision / Recall | 1.00 / 0.97 |

특성 중요도 상위:

| 특성 | 중요도 | Sigma 조건이 참조하는가 |
|---|---:|---|
| `user_name` | 0.1624 | 예 (`requestParameters.userName`, `userIdentity.arn`) |
| `user_type` | 0.1468 | 예 (`userIdentity.type`) |
| `user_agent` | 0.1396 | 예 |
| `access_key_id` | 0.1213 | 간접 (주체 식별) |
| `event_source` | 0.1159 | 예 |
| `event_name` | 0.1057 | 예 |

**상위 6개 중 5개가 Sigma 탐지 조건이 직접 참조하는 필드다.** 모델은 위협을 학습한 것이
아니라 룰의 `if`문을 재현하고 있다. INU-ML ADR-0002 §4.3의 결론이 라벨 소스와 무관하게,
그리고 저장소와 무관하게 성립한다는 추가 증거다.

## 5. 결정 (Decision)

- **최종 선택: B안. 라벨 소스를 SigmaHQ 룰 10종으로 교체하고, 시퀀스 특성 기반 라벨 규칙(규칙 6)을 제거한다.**
  - `_create_rule_based_labels` → `_create_sigma_labels`
  - `_check_definite_threat`를 Sigma 매칭 기반으로 교체. 매칭된 룰의 심각도로 신뢰도를
    정하고, 근거 문자열에 룰 제목과 MITRE 태그를 담는다
  - `matched_rules()` 추가 — 판정 근거 제시용
  - 모델 파일에 `label_source: sigma_rules`를 각인하고, 이 값이 없는 구버전 `.pkl`은
    **로드를 거부**한다. 라벨 체계가 바뀐 모델이 조용히 서빙되면 안 된다
  - 저장된 룰셋과 현재 룰셋이 다르면 경고. **룰이 곧 라벨이므로 룰셋이 바뀌면 모델이 학습한
    대상 자체가 달라진다**
  - `requirements.txt`에 `pysigma==1.5.0`
- 선택 이유 (트레이드오프 포함):
  - A안(공유 패키지)이 구조적으로는 옳지만, 저장소 경계와 배포 방식을 동시에 건드린다.
    지금 가장 큰 결함은 "라벨과 특성이 동일 필드를 공유한다"는 것이고, B안으로 즉시 제거된다.
  - 트레이드오프: **복제본은 그대로 남는다.** 두 저장소의 탐지기가 다시 갈라질 수 있으며,
    이번처럼 한쪽 결론이 다른 쪽에 도달하지 않는 일이 재발할 수 있다. A안은 폐기가 아니라
    보류다(§6).
  - AGENT의 시퀀스 특성과 운영 연동은 손대지 않았다. 시퀀스 특성은 라벨에서만 빼면 되고,
    특성으로서는 INU-ML v2와 같은 "누수 없는 행동 축"에 해당한다.
- **이 ADR은 "누수를 해결했다"고 주장하지 않는다.** 라벨 소스 교체만 완료됐고, 특성 축
  분리는 미완이다. 4.2가 그 증거다. 현재 상태를 정확히 쓰면
  **"라벨 소스 교체 완료 / 특성 분리 미완"** 이다.
- 채택하지 않은 대안이 더 나은 상황: 두 저장소를 한 팀이 함께 배포하게 되면 A안이 맞다.
  복제본 유지 비용이 이번 사례로 이미 드러났다.

## 6. 후속 작업 / 남은 리스크 (Follow-ups)

- **[다음] 특성 축 분리** — 가장 시급하다. Sigma 조건이 참조하는 원문 필드
  (`event_name`, `event_source`, `user_type`, `user_agent`, `user_name`)를 특성에서 제거하고,
  이미 구현되어 있는 시퀀스 특성 축으로 옮긴다. INU-ML의 v2 특성셋이 참고 구현이다.
  이 작업 전까지 F1 0.9104는 **탐지 성능이 아니라 룰 재현 충실도**로 읽어야 한다.
- **[리스크] 복제본이 남아 있다** — INU-ML과 AGENT의 탐지기가 다시 갈라질 수 있다.
  A안(공유 패키지)을 별도 과제로 유지한다.
- **[리스크] 기존 모델 파일 4개가 무효다** — `ml/models/*.pkl`은 전부 홈메이드 라벨로
  학습된 것이라 로드가 거부된다. 서비스 기동 전 재훈련이 필요하다.
  `app/services/ml_analysis_service.py`가 참조하는 `cloudTrail_v2.pkl` 포함.
- **[리스크] Sigma 룰 자체의 한계는 그대로 이월된다** — 룰 10종이 커버하지 못하는 공격은
  전부 "정상"으로 라벨링된다. `AssumeRole` misuse 룰 편중 문제도 동일
  (INU-ML ADR-0003 §4.1).
- **[다음] 룰셋 동기화 방법 결정** — 현재 `ml/src/core/rules/`는 INU-ML `src/rules/`의
  복사본이다. 룰이 곧 라벨이므로 두 저장소의 룰셋이 어긋나면 라벨이 어긋난다.
- **[다음]** `THREAT_TOOLS` / `SUSPICIOUS_KEYWORDS` / `HIGH_RISK_ACTIONS` 상수는 이제
  라벨 생성에 쓰이지 않고 특성 계산에만 쓰인다. 특성 축 분리 시 함께 정리한다.
