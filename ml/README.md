# CloudTrail 위협 탐지 시스템

AWS CloudTrail 로그에서 위협을 자동으로 탐지하는 Random Forest 기반 머신러닝 시스템입니다.

## 🎯 주요 기능

- ✅ **자동 라벨링**: JSON 로그만 제공하면 규칙 기반으로 자동 라벨링
- ✅ **실시간 탐지**: 단일 로그 예측 시간 < 100ms
- ✅ **높은 정확도**: Random Forest 알고리즘으로 F1 Score 0.9+ 달성
- ✅ **해석 가능성**: 특성 중요도 분석으로 판단 근거 제공
- ✅ **배치 분석**: 대용량 로그 데이터 일괄 처리
- ✅ **데이터베이스 연동**: 실제 운영 환경과의 완전 통합
- ✅ **명령행 도구**: 모델 훈련과 예측을 위한 CLI 제공

## 🚀 빠른 시작

### 1. 환경 설정
```bash
# 프로젝트 디렉토리로 이동
cd ml/

# 의존성은 메인 프로젝트에서 관리됩니다
```

### 2. 통합 실행 스크립트 사용
```bash
# 모델 훈련 (디렉토리에서)
python run_analysis.py train_model --source directory --dir data/0901/

# 모델 훈련 (단일 파일)
python run_analysis.py train_model --source json_file --file data/cloudtrail.json

# 위협 분석 (데이터베이스에서)
python run_analysis.py predict_threats --model models/detector.pkl --group-id your-group-id

# 단일 로그 파일 분석
python run_analysis.py predict_file --model models/detector.pkl --file logs/cloudtrail.json

# 배치 분석 (한 번만 실행)
python run_analysis.py batch_analyzer --model models/detector.pkl --once

```

## 📖 상세 사용법

### 통합 실행 스크립트 (`run_analysis.py`)

#### 기본 사용법
```bash
python run_analysis.py <script_name> [인수들]
```

#### 사용 가능한 스크립트
- `train_model` - 모델 훈련
- `predict_threats` - 최적화된 위협 예측 분석 (DB 기반)
- `predict_file` - 단일 로그 파일 위협 예측 분석
- `batch_analyzer` - 배치 분석

### 모델 훈련

#### 직접 실행
```bash
python -m src.core.train_model --source <SOURCE> [옵션들]
```

#### 통합 스크립트 실행
```bash
python run_analysis.py train_model --source directory --dir data/
```

#### 주요 옵션
| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--source` | 필수 | 데이터 소스 (`json_file`, `directory`) |
| `--file` | - | JSON 파일 경로 |
| `--dir` | - | JSON 파일들이 있는 디렉토리 |
| `--output` | `models/cloudtrail_threat_detector.pkl` | 모델 저장 경로 |
| `--min-logs` | `100` | 최소 로그 수 |

### 위협 예측

#### 데이터베이스 기반 분석
```bash
# 모든 그룹 분석
python run_analysis.py predict_threats --model models/detector.pkl

# 특정 그룹만 분석
python run_analysis.py predict_threats --model models/detector.pkl --group-id your-group-id

# 위협만 출력 (고신뢰도)
python run_analysis.py predict_threats --model models/detector.pkl --threats-only --min-confidence 0.8

# 데이터베이스 저장 없이 분석
python run_analysis.py predict_threats --model models/detector.pkl --no-save-db

# 최대 분석할 이벤트 수 제한
python run_analysis.py predict_threats --model models/detector.pkl --limit 1000
```

#### 주요 옵션
| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--model` | 필수 | 훈련된 모델 파일 경로 |
| `--group-id` | - | 특정 그룹만 분석 |
| `--limit` | - | 최대 분석할 이벤트 수 |
| `--threats-only` | False | 위협만 출력 |
| `--min-confidence` | 0.7 | 최소 신뢰도 |
| `--no-save-db` | False | 데이터베이스 저장 안함 |
| `--batch-size` | 5000 | 배치 처리 크기 |

### 단일 파일 예측

#### 기본 사용법
```bash
# 기본 분석
python run_analysis.py predict_file --model models/detector.pkl --file logs/cloudtrail.json

# 위협만 표시
python run_analysis.py predict_file --model models/detector.pkl --file logs/cloudtrail.json --threats-only

# 신뢰도 임계값 조정
python run_analysis.py predict_file --model models/detector.pkl --file logs/cloudtrail.json --min-confidence 0.8
```

#### 주요 옵션
| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--model` | 필수 | 훈련된 모델 파일 경로 |
| `--file` | 필수 | 분석할 CloudTrail JSON 파일 경로 |
| `--min-confidence` | 0.7 | 위협 탐지 최소 신뢰도 |
| `--threats-only` | False | 위협으로 탐지된 로그만 표시 |

### 배치 분석

#### 기본 사용법
```bash
# 한 번만 실행 (기본 동작)
python run_analysis.py batch_analyzer --model models/detector.pkl

# 특정 그룹만 분석
python run_analysis.py batch_analyzer --model models/detector.pkl --group-id your-group-id

# 배치 크기 조정
python run_analysis.py batch_analyzer --model models/detector.pkl --batch-size 2000
```

주의: batch_analyzer 스크립트의 연속 실행 및 스케줄 기능은 현재 구현 확인이 필요합니다.

## 📊 지원하는 CloudTrail 로그 형식

### JSON 파일 구조
```json
{
  "Records": [
    {
      "eventTime": "2024-01-15T10:30:00Z",
      "eventSource": "s3.amazonaws.com",
      "eventName": "GetObject",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "203.0.113.12",
      "userIdentity": {
        "type": "IAMUser",
        "userName": "john.doe"
      },
      "userAgent": "aws-console",
      "requestParameters": {
        "bucketName": "my-bucket"
      }
    }
  ]
}
```

### 지원 형식
- ✅ 표준 CloudTrail JSON (`{"Records": [...]}`)
- ✅ 단일 이벤트 JSON (`{"eventTime": ...}`)
- ✅ 이벤트 배열 JSON (`[{...}, {...}]`)
- ✅ 압축된 JSON.gz 파일

## 🔍 위협 탐지 규칙

시스템은 다음 규칙을 기반으로 자동 라벨링을 수행합니다:

### 1. Red Team 도구 탐지
```
User Agent에서 탐지되는 도구들:
- stratus-red-team, atomic-red-team
- metasploit, nmap, sqlmap, burp
- python-requests, boto3, curl
```

### 2. 의심스러운 리소스
```
버킷명이나 리소스명에 포함된 키워드:
- test, temp, stratus, red
- attack, exploit, poc
```

### 3. 시간 기반 패턴
```
- 심야 시간대 활동 (22:00-06:00)
- 주말 활동
- 프로그래매틱 접근 + 고위험 액션 조합
```

### 4. 고위험 액션
```
IAM 관련:
- CreateUser, DeleteUser
- AttachUserPolicy, DetachUserPolicy
- CreateAccessKey, DeleteAccessKey

S3 관련:
- PutBucketPolicy, DeleteBucket
```

### 5. 다중 의심 지표
```
3개 이상의 의심 지표가 함께 나타나는 경우:
- 에러 발생 + 프로그래매틱 접근 + 심야시간
- 고위험 액션 + 의심 리소스 + 외부 IP
```

## 📈 성능 지표

### 예상 성능
- **F1 Score**: 0.9+ (교차 검증 기준)
- **예측 시간**: ~90ms (초기 예측), ~10ms (후속 예측)
- **처리량**: 1,000+ logs/sec (배치 처리)

### 특성 중요도 예시
```
1. event_name (0.138)     - 어떤 액션인지
2. user_agent (0.122)     - 접근 도구
3. event_source (0.112)   - AWS 서비스
4. has_threat_tool (0.105) - 위협 도구 사용
5. is_high_risk_action (0.104) - 고위험 액션
```

## 🗂️ 프로젝트 구조

```
ml/
├── run_analysis.py               # 통합 실행 스크립트
├── src/
│   ├── core/                     # 핵심 ML 구성요소
│   │   ├── cloudtrail_threat_detector.py  # ML 모델 클래스
│   │   ├── train_model.py        # 모델 훈련 CLI
│   ├── analysis/                 # 분석 도구들
│   │   ├── predict_threats.py    # 위협 예측 CLI
│   │   └── batch_analyzer.py     # 배치 분석기
│   └── data/                     # 데이터 관리
│       ├── data_loader.py        # JSON 로딩
│       ├── db_data_loader.py     # DB 로딩
│       └── ml_result_saver.py    # 결과 저장
├── models/                       # 훈련된 모델 저장
├── data/                        # 훈련/테스트 데이터
├── logs/                        # 로그 파일들
└── notebooks/                   # 분석 노트북
```

## 🔧 개발 및 테스트

### 테스트 실행
```bash
# 통합 테스트 실행
python test_integration.py
```

### Python 코드로 사용
```python
from ml.src.core.cloudtrail_threat_detector import CloudTrailThreatDetector
from ml.src.data.file_data_loader import CloudTrailDataLoader

# 1. 파일에서 데이터 로드
loader = CloudTrailDataLoader()
logs = loader.load_from_json_file('data/cloudtrail.json')
valid_logs = loader.validate_logs(logs)

# 2. 모델 훈련
detector = CloudTrailThreatDetector()
training_results = detector.train(valid_logs)
detector.save_model('models/my_model.pkl')

# 3. 훈련된 모델로 예측
detector_loaded = CloudTrailThreatDetector()
detector_loaded.load_model('models/my_model.pkl')

result = detector_loaded.predict_single(log_event)
print(f"위협: {result['is_threat']}, 신뢰도: {result['confidence']:.3f}")

# 4. 배치 예측
results = detector_loaded.predict_batch_with_confidence(log_events_list)
```

### 데이터베이스 연동 사용
```python
from ml.src.data.db_data_loader import DatabaseDataLoader
from ml.src.data.ml_result_saver import MLResultSaver

# DB에서 로그 로드
db_loader = DatabaseDataLoader()
logs = db_loader.load_cloudtrail_events(group_id="your-group-id")

# ML 결과를 DB에 저장
result_saver = MLResultSaver()
result_saver.save_single_result(event_id, severity, confidence, result_data)
```

## 🚨 주의사항

### 데이터 요구사항
- **최소 로그 수**: 100개 이상 권장 (실용적으로는 1,000개+)
- **데이터 품질**: 필수 필드(`eventTime`, `eventSource`, `eventName`) 포함
- **다양성**: 정상 활동과 의심 활동이 골고루 포함된 데이터

### 모델 한계
- **규칙 기반 라벨링**: 새로운 공격 패턴 탐지에 제한
- **거짓 양성**: 정상이지만 규칙에 걸리는 경우 발생 가능
- **데이터 의존성**: 훈련 데이터와 다른 환경에서는 성능 저하

## 🔄 운영 워크플로우

### 1단계: 초기 모델 훈련
```bash
# 과거 CloudTrail 데이터로 초기 모델 생성
python run_analysis.py train_model --source directory --dir data/ --output models/production_v1.pkl
```

### 2단계: 실시간 분석 설정
```bash
# 데이터베이스에서 배치 분석 (한 번만)
python run_analysis.py batch_analyzer --model models/production_v1.pkl
```

### 3단계: 위협 모니터링
```bash
# 위협만 빠르게 확인
python run_analysis.py predict_threats --model models/production_v1.pkl --threats-only --min-confidence 0.8

# 특정 그룹만 분석
python run_analysis.py predict_threats --model models/production_v1.pkl --group-id "uuid-here"
```

### 4단계: 주기적 모델 업데이트
```bash
# 새로운 데이터로 모델 재훈련 (월 1회 권장)
python run_analysis.py train_model --source directory --dir updated_data/ --output models/production_v2.pkl
```

### 5단계: 통계 및 모니터링
현재 통계 및 성능 정보 조회 기능은 구현 확인이 필요합니다.

기본적으로는 분석 실행 시 콘솔에 출력되는 정보를 통해 결과를 확인할 수 있습니다.