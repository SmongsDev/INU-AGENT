from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from langchain_openai import OpenAIEmbeddings
from langchain_postgres import PGVector
from langchain.chat_models import init_chat_model
from langchain.tools.retriever import create_retriever_tool

from ..config import Config

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

def get_retriever(retrieve_cnt: int):
    retriever = vector_store.as_retriever(search_kwargs={"k": retrieve_cnt})
    return retriever

# Tool setup
def get_retriever_tool(retrieve_cnt: int):
    retrieve_cnt = retrieve_cnt or Config.RETRIEVE_CNT
    retriever_tool = create_retriever_tool(
        get_retriever(retrieve_cnt),
        "retrieve_document",
        "Search and return information about MITRE ATT&CK technique posts.",
    )
    return retriever_tool

def get_response_model(model_name: str):
    model = model_name or Config.MODEL_NAME
    response_model = init_chat_model(
        f"openai:{model}",
        temperature=0,
        openai_api_key=Config.OPENAI_API_KEY
    )
    return response_model

def get_grader_model(model_name: str = None):
    model = model_name or Config.MODEL_NAME
    grader_model = init_chat_model(
        f"openai:{model}",
    temperature=0,
    openai_api_key=Config.OPENAI_API_KEY
    )
    return grader_model
