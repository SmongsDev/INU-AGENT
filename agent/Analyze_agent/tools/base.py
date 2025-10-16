from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from langchain_openai import OpenAIEmbeddings
from langchain_postgres import PGVector
from langchain.chat_models import init_chat_model
from langchain.tools.retriever import create_retriever_tool

from agent.Analyze_agent.config import Config

# Database setup
engine = create_engine(Config.DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Vector store setup
embeddings = OpenAIEmbeddings(api_key=Config.OPENAI_API_KEY)
connection = engine.url.render_as_string(hide_password=False)

vector_store = PGVector(
    connection=connection,
    embeddings=embeddings,
    collection_name=Config.COLLECTION_NAME,
    relevance_score_fn="cosine",
)

def get_retriever(retrieve_cnt: int = None):
    """지정된 개수만큼 문서를 검색하는 retriever를 반환합니다."""
    cnt = retrieve_cnt or Config.RETRIEVE_CNT
    retriever = vector_store.as_retriever(search_kwargs={"k": cnt})
    return retriever

def get_retriever_tool(retrieve_cnt: int = None):
    """문서 검색 도구를 생성합니다."""
    retrieve_cnt = retrieve_cnt or Config.RETRIEVE_CNT
    retriever_tool = create_retriever_tool(
        get_retriever(retrieve_cnt),
        "retrieve_similar_events",
        "Search and return similar security events from the database.",
    )
    return retriever_tool

def get_model(model_name: str = None):
    """지정된 모델로 LLM 인스턴스를 생성합니다."""
    model = model_name or Config.MODEL_NAME
    return init_chat_model(
        f"openai:{model}",
        temperature=0.1,
        openai_api_key=Config.OPENAI_API_KEY
    )

def store_event(sql_result: str, event_id: str, is_false_positive: bool, confidence: float, explanation: str):
    """오탐 이벤트를 벡터 DB에 저장합니다."""
    from langchain_core.documents import Document
    
    vector_store.add_documents([
        Document(
            page_content=sql_result,
            metadata={
                'is_false_positive': is_false_positive,
                'event_id': event_id,
                'confidence': confidence,
                'explanation': explanation
            }
        )
    ])