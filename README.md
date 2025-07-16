# 오탐 탐지 에이전트

이 프로젝트는 보안 이벤트의 오탐을 자동으로 탐지하고 분석하기 위한 Python 기반 에이전트 프레임워크입니다. RAG(Retrieval Augmented Generation)와 LangGraph를 활용하여 이전 오탐 패턴을 학습하고 새로운 이벤트의 정오탐 여부를 판단합니다.

## 주요 특징

- **RAG 기반 오탐 학습**: 과거 오탐 데이터를 벡터 DB에 저장하고 유사도 기반 검색
- **LangGraph 워크플로우**: 이벤트 분석, 유사 패턴 검색, 정오탐 판단을 단계별로 처리
- **Supabase 벡터 저장소**: 오탐 패턴의 효율적인 저장 및 검색
- **OpenAI GPT-4 기반 분석**: 고도화된 언어 모델을 활용한 정확한 오탐 판단
- **모듈화된 구조**: 각 기능별 독립적인 모듈 구성으로 유지보수성 향상
- **확장 가능한 설계**: 새로운 분석 로직이나 저장소 추가 용이
- **테스트 자동화**: 단위/통합 테스트를 통한 안정성 확보

## 폴더 구조

```
agents/
  rag/                  # RAG 관련 모듈
    vector_store.py     # Supabase 벡터 스토어 설정
    document_converter.py # 이벤트 텍스트 변환
    retriever.py        # 유사 문서 검색
    supabase_client.py  # Supabase 클라이언트
  analyze_agent.py      # 분석 에이전트
  report_agent.py       # 리포트 생성 에이전트
  respond_agent.py      # 대응 에이전트
app/
  main.py              # API/서비스 진입점
  services/            # 서비스 레이어
  core/                # 핵심 설정/유틸리티
  api/                 # API 라우트
langgraph_flow/        # LangGraph 워크플로우
  nodes/               # 그래프 노드
    summarize.py       # 이벤트 요약
    retrieve.py        # 유사 이벤트 검색
    analyze.py         # 정오탐 분석
    store.py           # 오탐 저장
  graph.py             # 메인 그래프 정의
prompts/               # 프롬프트 템플릿
  analyze_prompt.txt   # 분석 프롬프트
tests/
  rag/                 # RAG 모듈 테스트
  data/                # 테스트용 샘플 데이터
  test_graph.py        # 그래프 워크플로우 테스트
  test_agents.py       # 에이전트 테스트
```

## 주요 모듈 설명

- **agents/rag/**
  - `vector_store.py`: Supabase 벡터 스토어 설정 및 관리
  - `document_converter.py`: 보안 이벤트를 텍스트로 변환
  - `retriever.py`: 유사 오탐 패턴 검색 로직
- **langgraph_flow/nodes/**
  - `summarize.py`: 이벤트 데이터 요약
  - `retrieve.py`: 유사 이벤트 검색
  - `analyze.py`: GPT-4 기반 정오탐 분석
  - `store.py`: 오탐 패턴 저장
- **prompts/**
  - 각 단계별 프롬프트 템플릿 관리
  - 분석 기준 및 출력 포맷 정의

## 설치 및 실행

1. **의존성 설치**

   ```bash
   pip install -r requirements.txt
   ```

2. **환경 변수 설정**

   ```bash
   # .env 파일 생성
   OPENAI_API_KEY=your_api_key
   SUPABASE_URL=your_supabase_url
   SUPABASE_SERVICE_ROLE_KEY=your_key
   LANGCHAIN_API_KEY=your_langsmith_key
   ```

3. **테스트 실행**

   ```bash
   # 전체 테스트 실행
   pytest

   # 특정 모듈 테스트
   pytest tests/test_graph.py
   pytest tests/rag/
   ```

4. **오탐 분석 실행**

   ```python
   from langgraph_flow.graph import process_security_event

   event = {
       "event_id": "evt-123",
       "timestamp": "2024-03-21T14:30:00Z",
       "detection_info": {
           "rule_id": "rule_001",
           # ... 이벤트 상세 정보
       }
   }

   result = process_security_event(event)
   print(f"오탐 여부: {result['is_false_positive']}")
   print(f"설명: {result['explanation']}")
   ```
